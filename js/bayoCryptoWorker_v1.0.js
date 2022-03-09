/*
 * bayoCryptoWorker_v1.0.js  
 */
importScripts('../ejs/sha256.min.js');
importScripts('bayoCryptoUtil_v1.0.js');

var encoder = new TextEncoder();
var decoder = new TextDecoder();

var isWORKER = true;

var workerCounter = 0;
var fileNameLibrary = [ 
    'seoul','angels','paris','zoo','airplane','miss','school','mars','moon','love','green','access',
    'point','beauty','soy','pluto','ping','pong','europe','beer','newyork','tokyo','next','red'
];

onmessage = function(evt){
    switch (evt.data[0]) { 
        case 'createBayoFile': // evt.data = [ oFiles, metaData{key,,} ]
            createBayoFile( evt.data[1], evt.data[2] );
            break;
        case 'extractBayoFile': // evt.data = [ file, metaData{key,,} ]
            extractBayoFile( evt.data[1], evt.data[2] );
            break;
        default:
            console.log('unknown message');
            break;
    }
    // console.log('metadata:', JSON.stringify( evt.data[2] ) );
}

/*
 * theFiles는 항상 FileList 형: 파일개수 1개 또는 여러개 가능 
 * metaData 통해  key, jpgMaskBuffer 전달.
 */
async function createBayoFile( theFiles , metaData ){  
    var isEncrypt = metaData.setup.isEncrypt;
    var encryptMode = metaData.setup.encryptMode;
    var headerImage;  
    if( metaData.jpgMaskBuffer ){   
        headerImage = metaData.jpgMaskBuffer;
    }else{         
        headerImage = new ArrayBuffer(0);
    }
    var processStartTime = performance.now();
    var fileInfo = { name: [], type: [], size: [], from: [] };  // fileInfo JSON 헤더 생성용.
        for(var i = 0; i< theFiles.length ; i++){
            fileInfo.name[i] = theFiles[i].name;
            fileInfo.type[i] = theFiles[i].type;
            var fileExt = theFiles[i].name;
            fileExt = fileExt.substr( fileExt.lastIndexOf('.')+1 );
            fileExt.toLocaleLowerCase();
            if(fileExt == 'vtt'){
                fileInfo.type[i] = 'text/vtt';
            } 
        }
        var tailPack = new Uint8Array(TAIL_LEN); //암호화 이후에 사용됨.
    var tail = {};
        tail.ivBin = self.crypto.getRandomValues(new Uint8Array(32)) ; 
    var ivStr = buf2hex(tail.ivBin.buffer);
        tail.EOI = new Uint8Array([0xFF, 0xD9]);
        tail.PID = new Uint8Array([0xBA, 0x40]);
        tail.nPower = new Uint8Array(1);
        tail.nPower[0] = NPOW_DEFAULT;
        tail.pwCheckSum = new Uint8Array(2);
        tail.pwCheckSum[0] = new Uint8Array( sha256.arrayBuffer( ivStr + metaData.pwStr.substr(0,1) ) )[0];
        tail.pwCheckSum[1] = new Uint8Array( sha256.arrayBuffer( ivStr + metaData.pwStr ) )[0];
        tail.hostFileSize = new Uint8Array(4);
        // tail.hashMode = new Uint8Array(1);   
        tail.encryptMode = new Uint8Array(4);  // A,B,C,D 4바이트 사용.  
    var hostFileSizeView = new DataView( tail.hostFileSize.buffer );
        hostFileSizeView.setUint32( 0, headerImage.byteLength );


// 1.키생성.
        if(isEncrypt){
            // 1-1. create WrappingKey ( alias: masterKey)
                var wrappingKey;
                if( encryptMode == CRYPTO_MODE["AES-CTR_BAYO"] || encryptMode == CRYPTO_MODE["AES-GCM_BAYO"] ){
                    wrappingKey = await getRawKeyByPBKDF2(  metaData.pwStr , ivStr , Math.pow(2,NPOW_DEFAULT)  );             
                }else if( encryptMode == CRYPTO_MODE["BAYO_GX"] ){ // BAYO-GX
                    wrappingKey =  nTimesHash( ivStr + metaData.pwStr ,  Math.pow(2,NPOW_DEFAULT)  );
                }else{
                    postMessage(['FAIL','Unknown Crypto Algorithm.']);
                }
                tail.masterKeyHash = new Uint8Array(  sha256.arrayBuffer( wrappingKey) );
            // 1-2. create rawByteCryptoKey ( randomValue )
                var rawByteCryptoKey = self.crypto.getRandomValues(new Uint8Array(32)) ;
                tail.encryptedCryptoKey = new Uint8Array( rawByteCryptoKey );
            // 1-3. encrypt rawByteCryptoKey ( with wrappingKey)  
                await bayoCrypto( wrappingKey, tail.encryptedCryptoKey , 0);    

        // AES-CTR.
            // CTR 모드 카운터 값규칙. index 0~15 중  8~11 4바이트값 unit당 1 증가.
            var key_AES_CTR = await self.crypto.subtle.importKey( "raw", rawByteCryptoKey.buffer, "AES-CTR",  false, ["encrypt"] );
            var counter = tail.ivBin.slice(0,16);  // coutner값은 iv 32바이트중 초기16바이트값 사용.
            var counterView = new DataView( counter.buffer, 8, 4);  // unit카운터는 참조 iv 랜덤값을 초기값으로 시작되고 unit 당 1씩 증가.
            
        //AES-GCM 모드용
                // unit단위로  ivBin 변조요함 **
            var key_AES_GCM = await self.crypto.subtle.importKey( "raw", rawByteCryptoKey.buffer, "AES-GCM",  false, ["encrypt"] );
            var ivBin12 = tail.ivBin.slice(0,12);
            var ivBin12View = new DataView( ivBin12.buffer , 0, 4);
        }

        var dataProcessBeginTime = performance.now();
// 2.실파일 암호화. 개수만큼 반복, unitSize 단위로 읽고, 개별 파일 크기까지 처리한뒤 다음 파일처리.
        var unitSize = UNIT_SIZE ;  //10MiB  
        var unitBuffer;// = new Uint8Array( unitSize );
        var lastFileDataBlobSize = 0;
        var fileDataBlob = new Blob( [], { type: 'application/octet-stream' } );
        for(i = 0; i < theFiles.length; i++){
            var pos = 0;
            var nSlice = Math.ceil( theFiles[i].size / unitSize );
            // console.log(`create --- filename: ${theFiles[i].name }  size: ${theFiles[i].size }  `)
            postMessage(['progressBegin', '['+(i+1).toString() + '/'+ theFiles.length.toString() + '] encrypting: ' + theFiles[i].name ]);
            if(isEncrypt){ //암호화 후 중첩
                if( encryptMode == CRYPTO_MODE["AES-CTR_BAYO"]  ){
                    for(var unit = 1 ; unit <= nSlice  ; unit++){  
                        unitBuffer = await asyncReadFileAsArrayBufferSlice( theFiles[i], pos, pos + unitSize ) ;
                        unitBuffer = await self.crypto.subtle.encrypt( { name: "AES-CTR", counter,length: 64 }, key_AES_CTR, unitBuffer );
                        fileDataBlob = new Blob( [fileDataBlob,unitBuffer], { type: 'application/octet-stream' } );
                        counterView.setUint32(0, counterView.getUint32(0) + 1 );  //unit카운터 증가. 
                        pos += unitSize;
                        postMessage( [ 'inprogress', (unit / nSlice * 100).toFixed(1) + "%" ] );  
                    }
                    
                }else if( encryptMode == CRYPTO_MODE["AES-GCM_BAYO"] ){
                    for(var unit = 1 ; unit <= nSlice  ; unit++){  
                        unitBuffer = await asyncReadFileAsArrayBufferSlice( theFiles[i], pos, pos + unitSize ) ;
                        unitBuffer = await self.crypto.subtle.encrypt( { name: "AES-GCM", iv: ivBin12 }, key_AES_GCM, unitBuffer );
                        fileDataBlob = new Blob( [fileDataBlob,unitBuffer], { type: 'application/octet-stream' } );
                        ivBin12View.setUint32(0, ivBin12View.getUint32(0) + 1 );  // iv 변조. 카운터 기능.
                        pos += unitSize;
                        postMessage( [ 'inprogress', (unit / nSlice * 100).toFixed(1) + "%" ] );  
                    }

                }
            }else{ // 비암호화 단순 중첩
                for(var unit = 1 ; unit <= nSlice  ; unit++){  
                    unitBuffer = await asyncReadFileAsArrayBufferSlice( theFiles[i], pos, pos + unitSize ) ;
                    fileDataBlob = new Blob( [fileDataBlob,unitBuffer], { type: 'application/octet-stream' } );
                    pos += unitSize;
                    postMessage( [ 'inprogress', (unit / nSlice * 100).toFixed(1) + "%" ] );  
                }
            }
        fileInfo.from[i] = lastFileDataBlobSize;
        fileInfo.size[i] = fileDataBlob.size - lastFileDataBlobSize;
        lastFileDataBlobSize = fileDataBlob.size; 
        // console.log(`-- name: ${theFiles[i].name } size: ${ theFiles[i].size }  `) ;
        // console.log(`-- from: ${fileInfo.from[i] } size: ${ fileInfo.size[i] } totalBlob.size: ${ fileDataBlob.size }  `) ;

        }

// 3. fileInfoPack, tailPack 마무리  blob to url 생성
    var fileInfoU8arr = encoder.encode(  JSON.stringify( fileInfo ) );
    var totalInfoLen = headerImage.byteLength + 4 + 32 + fileInfoU8arr.byteLength;
    var randomDummySize = parseInt( MAX_RANDOM_FILE_SIZE * Math.random() );
        totalInfoLen += randomDummySize;
    var addTo4x = getPad( totalInfoLen , 4);
    var fileInfoPack = new Uint8Array( 4 + 32 + fileInfoU8arr.byteLength + addTo4x +randomDummySize ); 
        fileInfoPack.set(fileInfoU8arr, fileInfoPackPos.fileInfo   ); 
    var fileInfoPackView = new DataView( fileInfoPack.buffer );
        fileInfoPackView.setUint16( fileInfoPackPos.addTo4x , addTo4x +randomDummySize ); 
        fileInfoPackView.setUint16( fileInfoPackPos.fileInfoLen , fileInfoU8arr.byteLength);

       var saveFilename;
       var fileExtName =  metaData.setup.jpgMask ? '.jpg' : '.bayo' ;
        if(isEncrypt){
            // 1. fileInfoPack 암호화
            await bayoCrypto( rawByteCryptoKey, fileInfoPack, 0); 
            // 2. tail 설정
            tailPack.set( tail.ivBin , tailPos.ivBin);
            tailPack.set( tail.masterKeyHash, tailPos.masterKeyHash );
            tailPack.set( tail.nPower, tailPos.nPower);
            tailPack.set( tail.pwCheckSum, tailPos.pwCheckSum );
            tailPack.set( tail.encryptedCryptoKey , tailPos.encryptedCryptoKey );
            tail.encryptMode[0] = encryptMode;   
            // 3. 파일명 변조 설정
            var n = parseInt( Math.random() * (fileNameLibrary.length - 1) );
            saveFilename  = fileNameLibrary[n] + '_'+buf2hex( tail.ivBin.buffer ).substr(0,2) + fileExtName;
        }else{
            tail.encryptMode[0] = CRYPTO_MODE["PLAINTEXT"]; 
            saveFilename = fileInfo.name[0] + fileExtName;
        }
        tailPack.set( tail.encryptMode, tailPos.encryptMode );
        tailPack.set( tail.hostFileSize, tailPos.hostFileSize);
        tailPack.set( tail.PID, tailPos.PID);
        tailPack.set( tail.EOI, tailPos.EOI);
        var createdBayoFileBlob = new Blob( [headerImage,  fileInfoPack, fileDataBlob, tailPack], { type: 'application/octet-stream' } );
        var objectURL = URL.createObjectURL( createdBayoFileBlob );
        var processTime = performance.now() - processStartTime;
        var dataProcessTime = performance.now() - dataProcessBeginTime;
        postMessage(['loggerMessage',`create --- spent time: ${(processTime/1000).toFixed(1)} sec.  data process speed: ${(createdBayoFileBlob.size / dataProcessTime/1000).toFixed(1)} MB/s `]  );
        // if( createdBayoFileBlob.size <= LOCALSTORAGE_FILESIZE_LIMIT){ 
            postMessage(['FILE_CREATED', objectURL, saveFilename, createdBayoFileBlob ]);
        // }else{
        //     postMessage(['FILE_CREATED', objectURL, saveFilename ]);
        // }
    }

    /* 
    theFile     입력되는 파일은 항상 1개다.   
    metaData    암호화 키와 암호화여부 : metaData{ key,  isEncrypted }  
    result      추출되는 파일은 1개(일반 파일)이거나 여러개(콜렉션)이다. 
     */
    async function extractBayoFile(theFile , metaData ){
        var processStartTime = performance.now();
        var tailBuffer = await asyncReadFileAsArrayBufferSlice( theFile, theFile.size - TAIL_LEN , theFile.size );
        var tailView = new DataView( tailBuffer);
        var fileInfoPackFrom = tailView.getUint32( tailPos.hostFileSize );
        var isEncrypted = metaData.isEncrypted ;
        var encryptMode = tailView.getUint8( tailPos.encryptMode );
        console.log('tail.encryptMode: ' + CRYPTO_MODE[ encryptMode ] );

        if(isEncrypted){  // 여기서는 전달된 키값의 확정 검증 후 맞으면 해독
            var nTimes = Math.pow(2, tailView.getUint8( tailPos.nPower ) );
            var ivBin = new Uint8Array( tailBuffer.slice( tailPos.ivBin , tailPos.ivBin + 32)) ;   
            var ivStr = buf2hex(ivBin.buffer);
            var rMasterKeyHashStr = buf2hex( tailBuffer.slice( tailPos.masterKeyHash , tailPos.masterKeyHash + 32 ) );
            var wrappingKey;
            console.time('hashKey');
            if( encryptMode == CRYPTO_MODE["AES-CTR_BAYO"] || encryptMode == CRYPTO_MODE["AES-GCM_BAYO"] ){
                wrappingKey =  await getRawKeyByPBKDF2(  metaData.pwStr , ivStr , nTimes  );    
            }else if( encryptMode == CRYPTO_MODE["BAYO_GX"] ){ // BAYO-GX
                wrappingKey =  nTimesHash( ivStr + metaData.pwStr ,  nTimes );
            }else{
                postMessage(['FAIL','Invalid Algorithm.']);
            }
            console.timeEnd('hashKey');

            if( rMasterKeyHashStr != sha256.hex( wrappingKey) ){
                postMessage(['wrongPass','Invalid password!' ]);
                return;
            }else{ //랩핑키 검증 성공.  cryptokey 추출 복원
                var encryptedCryptoKey = new Uint8Array( tailBuffer.slice( tailPos.encryptedCryptoKey,tailPos.encryptedCryptoKey +32) );
                await bayoCrypto( wrappingKey, encryptedCryptoKey, 0);
                var rawByteCryptoKey = encryptedCryptoKey;
            }
            // AES-CTR 모드 
            var key_AES_CTR = await self.crypto.subtle.importKey( "raw", rawByteCryptoKey.buffer, "AES-CTR",  false, ["decrypt"] );
            var counter = ivBin.slice(0,16);  // coutner값은 iv 32바이트중 초기16바이트값 사용.
            var counterView = new DataView( counter.buffer, 8, 4);  // unit카운터는 시작값은 iv기원값, 이후 unit 당 1씩 증가.

            // AES-GCM 모드
            var key_AES_GCM = await self.crypto.subtle.importKey( "raw", rawByteCryptoKey.buffer, "AES-GCM",  false, ["decrypt"] );
            var ivBin12 = ivBin.slice(0,12);
            var ivBin12View = new DataView( ivBin12.buffer, 0, 4);   
            
        }

    // fileInfoPack 부분읽어서 정확한 크기 확인. 암호화된경우 복호화후 확인가능
        var fileInfoPack = new Uint8Array( await asyncReadFileAsArrayBufferSlice( theFile, fileInfoPackFrom, fileInfoPackFrom + 4) ); 
        if(isEncrypted) await bayoCrypto( rawByteCryptoKey , fileInfoPack, 0);
        var fileInfoPackView = new DataView( fileInfoPack.buffer );
        var padd =  fileInfoPackView.getUint16( fileInfoPackPos.addTo4x );  
        var fileInfoLen = fileInfoPackView.getUint16( fileInfoPackPos.fileInfoLen ); 
    // fileInfoPack 전체 해독
        var fileInfoPackLen =  36 + fileInfoLen + padd;
        fileInfoPack = new Uint8Array( await asyncReadFileAsArrayBufferSlice( theFile, fileInfoPackFrom, fileInfoPackFrom + fileInfoPackLen ) );
        if(isEncrypted) await bayoCrypto( rawByteCryptoKey, fileInfoPack, 0);
        var fileInfoBuff =  new Uint8Array( fileInfoPack.buffer, 36 , fileInfoLen );
        try{
            var fileInfo = JSON.parse( decoder.decode( fileInfoBuff) );
            // console.log( 'decoded fileInfo Obj:' +  JSON.stringify( fileInfo) );
        }catch(err){
            postMessage(['wrongFileInfo','JSON fileinfo decoding error']);
        }

        var dataProcessBeginTime = performance.now();
        fileInfo.urls = []; 
        fileInfo.arrbuf = [];
        var fileDataFrom = fileInfoPackFrom + fileInfoPackLen ;
        var unitSize = UNIT_SIZE ;  //10MiB  
        if( encryptMode == CRYPTO_MODE["AES-GCM_BAYO"] ) unitSize += 16;  // GCM모드는 인증값 16바이트 함께 로딩.
        var unitBuffer;
        for(var i= 0; i< fileInfo.name.length ; i++ ){  // 파일안에 1~N개 파일 내장됨.
            postMessage(['progressBegin', 'extracting: ' + fileInfo.name[i] ]);
            var pos = fileDataFrom + fileInfo.from[i] ;  
            var fileDataBlob = new Blob( [], { type: 'application/octet-stream' } );
            var nSlice = Math.ceil( fileInfo.size[i] / unitSize );
            var lastUnitSize = fileInfo.size[i] % unitSize;
            if(isEncrypted){ 
                if( encryptMode == CRYPTO_MODE["AES-CTR_BAYO"] ){
                    try{
                        for(var unit = 1 ; unit <= nSlice  ; unit++){  
                            if(( unit == nSlice )&& lastUnitSize > 0){
                                unitBuffer = await asyncReadFileAsArrayBufferSlice( theFile, pos, pos + lastUnitSize ) ;
                            }else{
                                unitBuffer = await asyncReadFileAsArrayBufferSlice( theFile, pos, pos + unitSize ) ;
                            }
                            unitBuffer = await self.crypto.subtle.decrypt( { name: "AES-CTR", counter,length: 64 }, key_AES_CTR, unitBuffer );
                            fileDataBlob = new Blob( [fileDataBlob,unitBuffer], { type: 'application/octet-stream' } );
                            counterView.setUint32(0, counterView.getUint32(0) + 1 );  //unit카운터 증가
                            pos += unitSize;
                            postMessage( [ 'inprogress', (unit / nSlice * 100).toFixed(1) + "%" ] );  
                        }
                    }catch(err){
                        postMessage(['FAIL','AES-CTR Decryption error: '+ err ]); 
                        return
                    }
                }else if( encryptMode == CRYPTO_MODE["AES-GCM_BAYO"] ){
                    try{
                        for(var unit = 1 ; unit <= nSlice  ; unit++){  
                            if(( unit == nSlice )&& lastUnitSize > 0){
                                unitBuffer = await asyncReadFileAsArrayBufferSlice( theFile, pos, pos + lastUnitSize ) ;
                            }else{
                                unitBuffer = await asyncReadFileAsArrayBufferSlice( theFile, pos, pos + unitSize ) ;
                            }
                            unitBuffer = await self.crypto.subtle.decrypt( { name: "AES-GCM", iv: ivBin12 }, key_AES_GCM, unitBuffer );
                            fileDataBlob = new Blob( [fileDataBlob,unitBuffer], { type: 'application/octet-stream' } );
                            ivBin12View.setUint32(0, ivBin12View.getUint32(0) + 1 );  // 카운터방식 변조
                            pos += unitSize;
                            postMessage( [ 'inprogress', (unit / nSlice * 100).toFixed(1) + "%" ] );  
                        }
                    }catch(err){
                        postMessage(['FAIL','AES-GCM Decryption error: '+ err ]); 
                        return
                    }

                }else if( encryptMode == CRYPTO_MODE["BAYO_GX"] ){
                    var trim = fileInfo.from[i] % 32;
                    var trimPos;
                    for(var unit = 1 ; unit <= nSlice  ; unit++){  
                        if( unit == 1 && trim != 0){
                            trimPos = pos - trim;
                        }else{
                            trimPos = pos;  
                        }
                        if(( unit == nSlice )&& lastUnitSize > 0){
                            unitBuffer = await asyncReadFileAsArrayBufferSlice( theFile, trimPos, pos + lastUnitSize ) ;
                        }else{
                            unitBuffer = await asyncReadFileAsArrayBufferSlice( theFile, trimPos , pos + unitSize ) ;
                        }
                    var otpIndex = fileDataFrom + Math.floor( fileInfo.from[i] / 32 ) ;
                    var unitData = new Uint8Array( unitBuffer );
                    await bayoCrypto( rawByteCryptoKey, unitData , otpIndex  );
                        unitData =  unitData.slice(trim);
                        fileDataBlob = new Blob( [fileDataBlob, unitData], { type: 'application/octet-stream' } );
                        pos += unitSize;
                    postMessage( [ 'inprogress', (unit / nSlice * 100).toFixed(1) + "%" ] );  

                    }

                }

            }else{ // 비암호화 단순 중첩
                for(var unit = 1 ; unit <= nSlice  ; unit++){  
                    if(( unit == nSlice )&& lastUnitSize > 0){
                        unitBuffer = await asyncReadFileAsArrayBufferSlice( theFile, pos, pos + lastUnitSize ) ;
                    }else{
                        unitBuffer = await asyncReadFileAsArrayBufferSlice( theFile, pos, pos + unitSize ) ;
                    }
                    fileDataBlob = new Blob( [fileDataBlob,unitBuffer], { type: 'application/octet-stream' } );
                    pos += unitSize;
                    postMessage( [ 'inprogress', (unit / nSlice * 100).toFixed(1) + "%" ] );  

                }
    
            }
            // console.log(`--- blob file name: ${fileInfo.name[i]} extracted file blob size: ${fileDataBlob.size}`);
            var fileType = fileInfo.type[i].split('/')[0] ;
            if(fileType  == "text"){  //arrbuf는 메모리 복제 비용이 크므로 unitSize 이하 text인경우만 전달.
                if( fileInfo.size[i] == unitBuffer.byteLength ){
                // console.log(`attached text arrbuf: ${unitBuffer.byteLength} bytes.`);                
                    fileInfo.arrbuf[i]  =  unitBuffer ;
                }
                fileInfo.urls[i] = URL.createObjectURL( new Blob( [fileDataBlob ], {type: fileInfo.type[i] } ) );  //blob 타입변경.
            }else{
                fileInfo.urls[i] = URL.createObjectURL( fileDataBlob );  //octet 그대로
            }

            pos += fileInfo.size[i];
        }
        var totalDataSize = pos - fileDataFrom;
        var processTime = performance.now() - processStartTime;
        var dataProcessTime = performance.now() - dataProcessBeginTime;
        postMessage(['loggerMessage',`--- extract spent time: ${(processTime/1000).toFixed(1)} sec.  speed: ${(totalDataSize / dataProcessTime / 1000).toFixed(1)} MB/s `]  );
        postMessage(['FILE_EXTRACTED', fileInfo] );

}

/*
 *  V1.0    : multiple encryption algorithm. 
 * 
    Blob 구조
    
    + headerImage ( hostFile )
    + fileInfoPack :       pos size
        .addTo4x:       0   2B      | 4배수 맞춤과 랜덤바이트 사이트 함께 저장. 최대 64K바이트가능. MAX_RANDOM_FILE_SIZE 에 설정 
        .fileInfoLen:   2   2B
        .fileHash:      4   32B     //미사용.   메시지검증 필요시 GCM모드사용
        .fileInfo:      36  nB      | 파일 정보 JSON obj > string > encode > buffer  : 본 버퍼의 byteLength 크기가 fileInfoLen 값임.    
            \ name[i], type[i], from[i], size[i]

    + fileDataPack
        pos , size: flex

    + tailPack :                     SIZE :  v1.0 TAIL_LEN ==> 256Bytes     
        .ivBin: 0 32B               | 암호화 할때마다 생성되는 새로운 random 값. 
                                     파일 1회 암호화용도이므로 키생성용 salt와 counter 시작값 역활도 겸함.
        .masterKeyHash 32 32B       | hash( nTimesMasterKey )의 hash. 일치하면. 암호확정. 해독시작.
        .pwCheckSum    64 2B
                64: pwCheckSum1     | 암호첫글자 hash(iv+key) //패스워드 대충 검증용. sum1매칭시 1/256 확률
                65: pwCheckSum2     | 암호전체 hash( iv+key)  //패스워드 대충 검증용  sum1+sum2 매칭시 1/64K 확률
        .nPower:        66 1B       | nPower  중첩masterKey ntimes. 2^n승 값.  10:1024, 20:1MiB 30:1GiB 40:1TiB ... 
                                        pc급: 16:64K,  18: 256K(약0.5초) 
                                        PC 웹크롬: 0.5MH/sec.  모바일은 1/10 수준이므로 대중용으로는 50K가 한계임.
                                        고성능 기기 대비용으로 4바이트.  2^42가량.  16TH/sec 장비 (2^44/sec)대비용.
        .encryptedCryptoKey 32B     | 최종 파일 암호키
        . ~ reserved ~

        .encryptMode:   TAIL_LEN -12 4B     | total 4bytes. [A,B,C,D]  only A value is used.  B,C,D: reserved.  
                A == 0x00: BAYO-GX
                A == 0x01: AES-CTR_BAYO
                A == 0x02: AES-GCM_BAYO
                A == 0xFF: PLAINTEXT (No Encryption)  
        .hostFileSize:  TAIL_LEN - 8 4B     | jpg 숙주 파일의 크기.  없으면 0
        .PID:           TAIL_LEN - 4 2B     | 0xba 0x40  similar brand name: ba.yo
        .EOI:           TAIL_LEN - 2 2B      | JPEG EOI 값 삽입.   hostimagefile 끝에 이미 EOI가 있어서 필수는 아님. 

        */

