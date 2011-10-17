CREATE OR REPLACE PACKAGE PL_CRYPT
IS
/*******************************************************************************
 *
 * 暗号化・複合化処理
 * 
 * by m.yamaoka
 * 
 * ---------------------------------------------------------------------------
 * ※DBMS_CRYPTOパッケージの実行権限は、SYSユーザーのみ付与されている。
 *   したがって、各ユーザーで実行するためには
 *   そのユーザーに対してSYSユーザーからEXECUTE権限を付与させる必要がある。
 * 
 * -- SYSユーザーでログインして、下記のスクリプトを実行する
 * -- EXECUTE権限を付与
 * GRANT EXECUTE ON DBMS_CRYPTO TO USER;	-- "USER" を任意に置き換える。
 * ---------------------------------------------------------------------------
 * 
 *******************************************************************************/
/********************************************************************************
|MAIN			暗号化・複合化処理
*******************************************************************************/

	/*----------------------------------------
	|暗号化処理
	----------------------------------------*/
	FUNCTION ENCRYPT(
				  INC_STR				IN  VARCHAR2
				) RETURN VARCHAR2
	;

	/*----------------------------------------
	|複合化処理
	----------------------------------------*/
	FUNCTION DECRYPT(
				  INC_STR				IN  VARCHAR2
				) RETURN VARCHAR2
	;

END PL_CRYPT;
/
SHOW ERROR;
/

CREATE OR REPLACE PACKAGE BODY PL_CRYPT
IS
	CO_PKG_NM		CONSTANT	VARCHAR2(100)	:= 'PL_CRYPT';
	
	-- 暗号化キー
	CO_AES_KEY		CONSTANT	VARCHAR2(31)	:= 'crypt#key@aes';
	-- 暗号化アルゴリズム
	CO_DEF_CRYPT	CONSTANT	PLS_INTEGER		:= DBMS_CRYPTO.ENCRYPT_AES256
												 + DBMS_CRYPTO.CHAIN_CBC
												 + DBMS_CRYPTO.PAD_PKCS5;
	-- 暗号化キー(RAW型)
	MO_AES_KEY					RAW(64);
	-- 暗号化フラグ（0:暗号化しない、1：暗号化する）
	MN_ENCRYPTION_FLAG			NUMBER(1);
	
	/***************************************************************************
	|名　称：ENCRYPT
	|機　能：暗号化処理
	|引　数：INC_STR				= 暗号化文字列
	|戻り値：暗号化データ（RAW型）
	***************************************************************************/
	FUNCTION ENCRYPT(
				  INC_STR					IN  VARCHAR2
				) RETURN VARCHAR2
	IS
		--// 定数宣言
		CO_PGID			CONSTANT	VARCHAR2(40)	:= 'ENCRYPT';
		CO_ERRMSG		CONSTANT	VARCHAR2(200)	:= '【' || CO_PKG_NM || '.' || CO_PGID || '】';

		O_STR_RAW		RAW(512);
		O_ENCRYPT_RAW	RAW(512);
		C_ENCRYPT_STR	VARCHAR2(512);

	BEGIN
		
		C_ENCRYPT_STR := INC_STR;
		
		IF MN_ENCRYPTION_FLAG = 1 THEN
			-- VARCHAR2型をRAW型に変換
			O_STR_RAW := UTL_I18N.STRING_TO_RAW(INC_STR, 'AL32UTF8');
			-- 暗号化処理
			O_ENCRYPT_RAW := DBMS_CRYPTO.ENCRYPT(O_STR_RAW, CO_DEF_CRYPT, MO_AES_KEY);
			-- 暗号文をVARCHAR2型に変換
			C_ENCRYPT_STR := TO_CHAR(O_ENCRYPT_RAW);
		END IF;

		RETURN C_ENCRYPT_STR;

	EXCEPTION
		WHEN OTHERS THEN
			RAISE_APPLICATION_ERROR(-20003, SQLERRM || CO_ERRMSG);
	END ENCRYPT;

	/***************************************************************************
	|名　称：DECRYPT
	|機　能：複合化処理
	|引　数：INC_STR				= 暗号化データ
	|引　数：INC_STR				= 暗号化データ
	|戻り値：複合文
	***************************************************************************/
	FUNCTION DECRYPT(
				  INC_STR				IN  VARCHAR2
				) RETURN VARCHAR2
	IS
		--// 定数宣言
		CO_PGID			CONSTANT	VARCHAR2(40)	:= 'DECRYPT';
		CO_ERRMSG		CONSTANT	VARCHAR2(200)	:= '【' || CO_PKG_NM || '.' || CO_PGID || '】';

		O_DECRYPT_RAW	RAW(512);
		C_STR			VARCHAR(512);

	BEGIN
		
		C_STR := INC_STR;
		
		IF MN_ENCRYPTION_FLAG = 1 THEN
			-- パラメータが半角スペースのみの場合、複合化処理は行わずに終了する
			IF TRIM(INC_STR) IS NULL THEN
				RETURN INC_STR;
			END IF;
			
			-- 複合化処理
			O_DECRYPT_RAW := DBMS_CRYPTO.DECRYPT(INC_STR, CO_DEF_CRYPT, MO_AES_KEY);
			-- RAW型データをVARCHAR2型に変換
			C_STR := UTL_I18N.RAW_TO_CHAR(O_DECRYPT_RAW, 'AL32UTF8');
		END IF;
		
		RETURN C_STR;

	EXCEPTION
		WHEN OTHERS THEN
			RAISE_APPLICATION_ERROR(-20003, SQLERRM || CO_ERRMSG);
	END DECRYPT;


	/****************************************
	||	パッケージ初期化部
	****************************************/
	BEGIN
	DECLARE
	BEGIN
	
		--// 暗号化キー文字列をRAW型に変換してインスタンス変数に保持する
		MO_AES_KEY := UTL_I18N.STRING_TO_RAW(RPAD(CO_AES_KEY, 32, '*'), 'AL32UTF8');

		--// 暗号化フラグをセット（0:暗号化しない、1：暗号化する）
		MN_ENCRYPTION_FLAG := 1;
		
	EXCEPTION
		WHEN OTHERS THEN
			MN_ENCRYPTION_FLAG := 0;
			NULL;
	END;

----------------------------------------------------------------------------------
END PL_CRYPT;
/
SHOW ERROR;
/
