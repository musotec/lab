/*
 * bayoCryptoUtil.js
 */
const APP_URL = "https://mediakeeper.github.io";
const NPOW_DEFAULT = 16; // 2^16승. 64K.
const TAIL_LEN = 256;
// const LOCALSTORAGE_FILESIZE_LIMIT = Math.pow(2,20) * 500 ; 
const MAX_FILE_SIZE = Math.pow(2,33);  // 허용 파일크기 한도 설정. 33->8GiB
const MAX_RANDOM_FILE_SIZE = 1000;  //padd 되는 파일크기 랜덤화 가변폭.
const MAX_HASHCHECK_FILE_SIZE = 100000000;  // 고용량 파일은 hash digest 생략.
const CRYPTO_MODE = {  'BAYO_GX': 0, 'AES-CTR_BAYO': 1, 'AES-GCM_BAYO': 2 , 'PLAINTEXT': 255,
                        0: 'BAYO_GX' , 1: 'AES-CTR_BAYO' , 2: 'AES-GCM_BAYO' , 255: 'PLAINTEXT' };
const UNIT_SIZE = Math.pow(2,20) *10; // 10MiB
var tailPos ={ ivBin: 0, masterKeyHash: 32 ,pwCheckSum: 64, nPower: 66 , encryptedCryptoKey: 67,
           encryptMode: TAIL_LEN - 12, hostFileSize: TAIL_LEN - 8 , PID: TAIL_LEN - 4  , EOI: TAIL_LEN -2 };
var fileInfoPackPos = { addTo4x: 0, fileInfoLen: 2, fileHash: 4 ,fileInfo: 36 };

function numberWithCommas(x) { return x.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");}
function buf2hex(buffer) {  return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join(''); } //arraybuffer를 hex문자열로
function getPad(v,p){ return (v % p) ? p - (v % p) : 0;  }  //v가 p의 배수 되기위해 더해질 값 return  


/*
    출력; 32B arraybuffer  ( sha256hash 결과형)
*/
function getRawKeyByPBKDF2( keySrc , saltSrc , ntime){
    return crypto.subtle.importKey(
        "raw",
        sha256.arrayBuffer( keySrc ),
        {name: "PBKDF2"},
        false,
        ["deriveBits"]
    ).then( function(rawKey){
       return crypto.subtle.deriveBits(
            {
            "name": "PBKDF2",
            salt: sha256.arrayBuffer( saltSrc ).slice(0,16),
            "iterations": ntime,
            "hash": "SHA-256"
            },
            rawKey,
            256
        );
    });
    
}


/* 
    sha256 사용법.
입력:
    data:  문자열, UTF-8문자열 입력시 인코딩됨, array, typedarray, arraybuffer 모두 지원
출력:
    sha256.hex('') //hex 문자열 출력. 생략시 동일
    sha256.array('') // 그냥 array 배열형
    sha256.digest('') // 그냥 array 배열형
    sha256.arrayBuffer('') //arraybuffer 반환 
*/


/* nTimesHash.   (PBKDF2 와 유사한 용도)
최초 srcData로 arrayBuffer화 1회 + n회.  총hash개 연산수는 n+1번임.
입력: srcData:  참고로 문자열, UTF-8문자열 입력시 인코딩됨, array, typedarray, arraybuffer 모두 지원
        bayoCrypto에서는  pwStr+ivStr 합쳐서 입력
출력: sha256.arrayBuffer() //arraybuffer 반환 
*/

function nTimesHash( srcData, n ){
    var hashSum = sha256.arrayBuffer( srcData );
    for(var i=0; i< n ; i++) hashSum =  sha256.arrayBuffer( hashSum) ; 
    return hashSum
}
function getHashRate( nTimes ){
    var t1 = performance.now();
    var buf = new ArrayBuffer(32);
        for(var i=0;i< nTimes; i++){
        buf = sha256.arrayBuffer(buf);
        }
    var ms = performance.now() - t1;
    return (nTimes * 1000 / ms).toFixed(0);
}
function printHashRate( nTimes ){
    var nps = getHashRate(nTimes);
    var hashRate;// = nps;
    for (var aMultiples = ["K", "M", "G", "T", "P", "E", "Z", "Y"], nMultiple = 0, nApprox = nps / 1024; nApprox > 1; nApprox /= 1024, nMultiple++) {
    hashRate = nApprox.toFixed(3) +' '+ aMultiples[nMultiple] + "H/s ( " + nps + " hash/sec )";
    }
    return 'sha256 hash power: '+ hashRate ;
}


// return ArrayBuffer of the file
function asyncReadFileAsArrayBuffer(theFile  ){
    return new Promise( function(resolve, reject){
        if(theFile == undefined){ reject('no file selected'); }
        if(theFile.size >= MAX_FILE_SIZE  ){
            reject('bayoCryptoUtil: max file size over.');
        }
        var reader = new FileReader();
        reader.onload = function( e) { resolve( reader.result ); };
        // if(isWORKER){ 
        //     reader.onprogress = function(e){
        //         var progressMsg = "step 1/4: memory loading. "+ (e.loaded / e.total * 100).toFixed(0) + "%";
        //         postMessage(['loadprogress', progressMsg]);
        //     }
        // }
        reader.readAsArrayBuffer(theFile) ;    
        });
    }

// return ArrayBuffer of the file
function asyncReadFileAsArrayBufferSlice(theFile ,start, end  ){
    return new Promise( function(resolve, reject){
        if(theFile == undefined){ reject('no file selected'); }
        if( (end - start) >= MAX_FILE_SIZE  ){ reject('file size over. max file size: ' + MAX_FILE_SIZE);}
        var reader = new FileReader();
        reader.onload = function( e) { resolve( reader.result );  };
        reader.readAsArrayBuffer(theFile.slice( start, end ) ) ;    
    });
}


/*
    문자열을 UTF8호환 TextEncoder로 encode 하여 버퍼로 변환후 암호화한뒤 base64 문자열로 반환한다.
    특징 및 제한
    1. randomize size.  : 매 암호화시마다 암호결과값의 크기가 달라진다.(현재 0~64 랜덤추가됨)   메시지폭 검사 대항.
    2. control strength of key:  중첩해쉬를 통한 암호키 생성방식으로 강도 조절. 
                                2 ^ n 번 중첩연산됨. n은 10~16 충분. 너무크면 시간이 오래걸리므로 주의.
                                현재, 16까지만 되도록 제한걸어둠. 

    3. 메시지 크기는 2 ^ 16 까지만 되도록 제한함. 문자열이라 64KB정도로 제한함. 

    암호화 결과 데이타 버퍼 구조.
    +---------+-------+----------+
    데이타명:   index   bytesize.
    msg:        [0]     1 ~ 64KB 
    salt:       [-35]   32 Bytes
    nTimes:     [-3]    1 Bytes
    msgLen:     [-2]    2 Bytes
*/

   var msgPos = { msg: 0  , salt: -35, nTimes: -3, msgLen: -2  };
    async function encryptMsg( msg , key , ntimesKey){
        var msgBuffer = encoder.encode( msg );
        var realMsgLen = msgBuffer.byteLength;
        var saltBin = self.crypto.getRandomValues(new Uint8Array(32)) ; 
        // var saltBin = new Uint8Array(32) ; 
        var randomSize = realMsgLen + parseInt( self.crypto.getRandomValues(new Uint8Array(1))[0] / 4   ) ;  // 0~63.
        // var randomSize = 4;
        console.log( 'msg buf size: ' + randomSize);
        if( randomSize > 65536 ){
            console.log('over msg size limit: it support about 64KB ascii characters.  or about 20K  UTF-8 characters ');
            return "";
        }
        if( ntimesKey > 16 ){
            console.log('over ntimeKey limit: 16 max.');
            return "";
        }
        //다른형식의 데이타나 손상된 메시지 체크도 필요함.  이값이 너무 커지면 멈춤. 
//현재는 특정사이트용 간단한 구현.  공개lib형의 경우 추가로 메시지 체크섬,  메시지 시간, 규칙, 에러핸들링 추가요함.

        var msgBufferExpanded = new Uint8Array( randomSize );
        msgBufferExpanded.set( msgBuffer);
        var saltStr = buf2hex(saltBin.buffer);
        var masterKeyArr = new Uint32Array( nTimesHash( saltStr + key ,  Math.pow( 2, ntimesKey ) ) );
        await bayoCrypto( masterKeyArr, msgBufferExpanded, 0);
        var base64Buffer = new Uint8Array( msgBufferExpanded.byteLength + saltBin.byteLength + 3);
        base64Buffer.set( msgBufferExpanded );
        base64Buffer.set( saltBin , base64Buffer.byteLength + msgPos.salt );
        base64Buffer[base64Buffer.byteLength + msgPos.nTimes] = ntimesKey;
        var dv = new DataView( base64Buffer.buffer );
        dv.setUint16(base64Buffer.byteLength + msgPos.msgLen , msgBufferExpanded.byteLength );
        return base64js.fromByteArray( base64Buffer );
    }

    var testmsg = "";
    function setMsg( msg ){
        testmsg = "";
         for(var i=0; i< 10000; i++){
             testmsg += msg;
         } 
         console.log('length of testmsg: ' + testmsg.length );
    }

    
    async function decryptMsg( b64msg , key ){
        var totalBuffer = base64js.toByteArray(b64msg);
        var dv = new DataView( totalBuffer.buffer);
        var msgLen = dv.getUint16( totalBuffer.byteLength + msgPos.msgLen );
        var expandedMsgBuffer = totalBuffer.slice( 0 , msgLen );
        var saltBin = totalBuffer.slice( msgPos.salt , msgPos.nTimes );
        var ntimesKey = dv.getUint8( totalBuffer.byteLength + msgPos.nTimes );
        if(ntimesKey > 16 ){
            console.log('warning: too much ntimesKey:' + ntimesKey);
            return "ntimes 값이 너무큰것같음";
        }
        var saltStr = buf2hex(saltBin.buffer);
        var masterKeyArr = new Uint32Array( nTimesHash( saltStr + key ,  Math.pow( 2, ntimesKey ) ) );
        await bayoCrypto( masterKeyArr, expandedMsgBuffer, 0);
        var realMsgBuffer = expandedMsgBuffer.slice(0, expandedMsgBuffer.indexOf(0) );
        var msg = decoder.decode( realMsgBuffer );
        return msg;
    }

    

/*
bayoCrypto 시간제한형 고용량 데이타처리를 비 워커에서 작동시.
encryption & decryption 동일.  bayoCryptoGenerator 사용.
argument1: cryptoKey  dataType: Uint8Array(32) or ArrayBuffer(32)
argument2: dataBuffer    dataType: Uint8Array(n)
argument3: otpStartIndex dataType: number 0~ 2^32 -1 
arg4: timeLimit msec.  
*/
function bayoCryptoTimeLimit(cryptoKey, dataBuffer  , otpStartIndex , timeLimit ){ 

        return new Promise( function(resolve, reject){
            if (cryptoKey === null || cryptoKey === undefined) {
                reject('bayoCrypto: cryptoKey is null or undefined');
              } else if (cryptoKey.constructor === ArrayBuffer) {
                cryptoKey = new Uint8Array(cryptoKey);
              }
            //cryptoKey check
            if( cryptoKey.byteLength != 32 ){
                reject('bayoCrypto: cryptoKey byteLength err');
                return;
            }
            if(dataBuffer == undefined){
                // console.log("전달된 buffer 없음");
                reject('buffer오류');
                return;
            }
            var gStartTime = performance.now();
            var g = bayoCryptoGenerator(cryptoKey, dataBuffer, otpStartIndex , timeLimit ); 
            var gTimer = setInterval( function(){
                var result = g.next();
                if(result.done){
                    var totalBytes = dataBuffer.byteLength;
                    var spentTime = performance.now() - gStartTime;
                    var binRate = totalBytes / spentTime * 1000;
    // if(!isWORKER)  console.log(`g. spent time: ${spentTime.toFixed()}ms.  encrypt speed: ${binRate.toFixed()}bytes/sec. ` );
                    resolve( dataBuffer );
                    clearInterval(gTimer);
                }
            } , timeLimit );
        });

}

function* bayoCryptoGenerator(cryptoKey, u8Arr , otpStartIndex , yieldTimeLimit ){  //yield timeLimit: msec
    var otpMasterKeyArr = new Uint32Array(9);
    var cryptoKeyArr = new Uint32Array(cryptoKey.buffer );
    otpMasterKeyArr.set( cryptoKeyArr );
    otpMasterKeyArr[8] = otpStartIndex;
    var nBytes = u8Arr.byteLength;
    var nTimes = Math.ceil( nBytes / 32);   //최소값 1   ; 필요한 otp 개수
    var lastTime = nTimes - 1;              //최소값 0
    var nRemains = nBytes % 32;
    var buf32Len = Math.floor( nBytes / 4); //byteLength / 4 => 4바이트의 배수 
    // console.log(`bayoCrypto src u8Arr .byteOffset: ${u8Arr.byteOffset} .byteLength: ${u8Arr.byteLength}  1/4 floored => buf32Len: ${buf32Len}`);
    
    //주의. 이부분은 새로운 버퍼 생성후 복제가 아니고 dataview 생성임. 공용체임.
    var buf32 = new Uint32Array( u8Arr.buffer, u8Arr.byteOffset, buf32Len );

    var timer1 = performance.now();
    for(var i= 0; i < nTimes; i++){ //32바이트 단위로 원본 파일읽어서 otp 연산.
        //1. indexed psudo otp 생성 
        otpMasterKeyArr[8]++;
        var potp = sha256.arrayBuffer( otpMasterKeyArr.buffer );    // 32b
        var potp32 = new Uint32Array(potp);
        var ts = performance.now() - timer1;
        if( ts > yieldTimeLimit ){   
            yield (i / nTimes * 100).toFixed(1) + "%";  // 저용량처리에 워커까지 사용되므로 yield 불필요.
            timer1 = performance.now(); //복귀후 시작 시간.
        }
        if( i == lastTime && nRemains != 0 ){ // 32바이트 이하 (나머지 Byte 연산)  
            var potp8 = new Uint8Array( potp);                   
            for(var q = nBytes - nRemains, r = 0 ; r< nRemains ; r++){   //최대 31번
                // console.log(`q:${q} r:${r}`);
                u8Arr[q++] ^= potp8[r];    //q;버퍼의 index   r; otp의 index 
            }                
        }else{ // 4Bytes 단위 8회 연산
            for(var ib=0; ib< 8; ib++) buf32[ i * 8 + ib] ^= potp32[ib];
                
        } 
    }
}

/*
bayoCrypto 대칭키 암호알고리즘.   
encryption & decryption 동일.  bayoCryptoGenerator 사용.
argument1: cryptoKey  dataType: Uint8Array(32) or ArrayBuffer(32)
argument2: dataBuffer    dataType: Uint8Array(n)
argument3: otpStartIndex dataType: number 0~ 2^32 -1 
*/
function bayoCrypto(cryptoKey, dataBuffer  , otpStartIndex ){

        return new Promise( function(resolve, reject){
            if (cryptoKey === null || cryptoKey === undefined) {
                reject('bayoCrypto: cryptoKey is null or undefined');
              } else if (cryptoKey.constructor === ArrayBuffer) {
                cryptoKey = new Uint8Array(cryptoKey);
              }
            //cryptoKey check
            if( cryptoKey.byteLength != 32 ){
                reject('bayoCrypto: cryptoKey byteLength err');
                return;
            }
            if(dataBuffer == undefined){
                // console.log("전달된 buffer 없음");
                reject('buffer오류');
                return;
            }
            // var gStartTime = performance.now();
            // var g = bayoCryptoGenerator(cryptoKey, dataBuffer, otpStartIndex);

            var u8Arr = dataBuffer;
            var otpMasterKeyArr = new Uint32Array(9);
            var cryptoKeyArr = new Uint32Array(cryptoKey.buffer );
            otpMasterKeyArr.set( cryptoKeyArr );
            otpMasterKeyArr[8] = otpStartIndex;
            var nBytes = u8Arr.byteLength;
            var nTimes = Math.ceil( nBytes / 32);   //최소값 1   ; 필요한 otp 개수
            var lastTime = nTimes - 1;              //최소값 0
            var nRemains = nBytes % 32;
            var buf32Len = Math.floor( nBytes / 4); //byteLength / 4 => 4바이트의 배수 
            // console.log(`bayoCrypto src u8Arr .byteOffset: ${u8Arr.byteOffset} .byteLength: ${u8Arr.byteLength}  1/4 floored => buf32Len: ${buf32Len}`);
            
            //주의. 이부분은 새로운 버퍼 생성후 복제가 아니고 dataview 생성임. 공용체임.
            var buf32 = new Uint32Array( u8Arr.buffer, u8Arr.byteOffset, buf32Len );
        
            var timer1 = performance.now();
            for(var i= 0; i < nTimes; i++){ //32바이트 단위로 원본 파일읽어서 otp 연산.
                //1. indexed psudo otp 생성 
                otpMasterKeyArr[8]++;
                var potp = sha256.arrayBuffer( otpMasterKeyArr.buffer );    // 32b
                var potp32 = new Uint32Array(potp);
                var ts = performance.now() - timer1;
                if( isWORKER && ts > 30){  // 33fps 
                    postMessage(['inprogress', (i / nTimes * 100).toFixed(1) + "%"] );
                    timer1 = performance.now(); //복귀후 시작 시간.
                }
                if( i == lastTime && nRemains != 0 ){ // 32바이트 이하 (나머지 Byte 연산)  
                    var potp8 = new Uint8Array( potp);                   
                    for(var q = nBytes - nRemains, r = 0 ; r< nRemains ; r++){   //최대 31번
                        // console.log(`q:${q} r:${r}`);
                        u8Arr[q++] ^= potp8[r];    //q;버퍼의 index   r; otp의 index 
                    }                
                }else{ // 4Bytes 단위 8회 연산
                    for(var ib=0; ib< 8; ib++) buf32[ i * 8 + ib] ^= potp32[ib];
                        
                } 
            }
            resolve( dataBuffer );
        });

}
