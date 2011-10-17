CREATE OR REPLACE PACKAGE PL_CRYPT
IS
/*******************************************************************************
 *
 * �Í����E����������
 * 
 * by m.yamaoka
 * 
 * ---------------------------------------------------------------------------
 * ��DBMS_CRYPTO�p�b�P�[�W�̎��s�����́ASYS���[�U�[�̂ݕt�^����Ă���B
 *   ���������āA�e���[�U�[�Ŏ��s���邽�߂ɂ�
 *   ���̃��[�U�[�ɑ΂���SYS���[�U�[����EXECUTE������t�^������K�v������B
 * 
 * -- SYS���[�U�[�Ń��O�C�����āA���L�̃X�N���v�g�����s����
 * -- EXECUTE������t�^
 * GRANT EXECUTE ON DBMS_CRYPTO TO USER;	-- "USER" ��C�ӂɒu��������B
 * ---------------------------------------------------------------------------
 * 
 *******************************************************************************/
/********************************************************************************
|MAIN			�Í����E����������
*******************************************************************************/

	/*----------------------------------------
	|�Í�������
	----------------------------------------*/
	FUNCTION ENCRYPT(
				  INC_STR				IN  VARCHAR2
				) RETURN VARCHAR2
	;

	/*----------------------------------------
	|����������
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
	
	-- �Í����L�[
	CO_AES_KEY		CONSTANT	VARCHAR2(31)	:= 'crypt#key@aes';
	-- �Í����A���S���Y��
	CO_DEF_CRYPT	CONSTANT	PLS_INTEGER		:= DBMS_CRYPTO.ENCRYPT_AES256
												 + DBMS_CRYPTO.CHAIN_CBC
												 + DBMS_CRYPTO.PAD_PKCS5;
	-- �Í����L�[(RAW�^)
	MO_AES_KEY					RAW(64);
	-- �Í����t���O�i0:�Í������Ȃ��A1�F�Í�������j
	MN_ENCRYPTION_FLAG			NUMBER(1);
	
	/***************************************************************************
	|���@�́FENCRYPT
	|�@�@�\�F�Í�������
	|���@���FINC_STR				= �Í���������
	|�߂�l�F�Í����f�[�^�iRAW�^�j
	***************************************************************************/
	FUNCTION ENCRYPT(
				  INC_STR					IN  VARCHAR2
				) RETURN VARCHAR2
	IS
		--// �萔�錾
		CO_PGID			CONSTANT	VARCHAR2(40)	:= 'ENCRYPT';
		CO_ERRMSG		CONSTANT	VARCHAR2(200)	:= '�y' || CO_PKG_NM || '.' || CO_PGID || '�z';

		O_STR_RAW		RAW(512);
		O_ENCRYPT_RAW	RAW(512);
		C_ENCRYPT_STR	VARCHAR2(512);

	BEGIN
		
		C_ENCRYPT_STR := INC_STR;
		
		IF MN_ENCRYPTION_FLAG = 1 THEN
			-- VARCHAR2�^��RAW�^�ɕϊ�
			O_STR_RAW := UTL_I18N.STRING_TO_RAW(INC_STR, 'AL32UTF8');
			-- �Í�������
			O_ENCRYPT_RAW := DBMS_CRYPTO.ENCRYPT(O_STR_RAW, CO_DEF_CRYPT, MO_AES_KEY);
			-- �Í�����VARCHAR2�^�ɕϊ�
			C_ENCRYPT_STR := TO_CHAR(O_ENCRYPT_RAW);
		END IF;

		RETURN C_ENCRYPT_STR;

	EXCEPTION
		WHEN OTHERS THEN
			RAISE_APPLICATION_ERROR(-20003, SQLERRM || CO_ERRMSG);
	END ENCRYPT;

	/***************************************************************************
	|���@�́FDECRYPT
	|�@�@�\�F����������
	|���@���FINC_STR				= �Í����f�[�^
	|���@���FINC_STR				= �Í����f�[�^
	|�߂�l�F������
	***************************************************************************/
	FUNCTION DECRYPT(
				  INC_STR				IN  VARCHAR2
				) RETURN VARCHAR2
	IS
		--// �萔�錾
		CO_PGID			CONSTANT	VARCHAR2(40)	:= 'DECRYPT';
		CO_ERRMSG		CONSTANT	VARCHAR2(200)	:= '�y' || CO_PKG_NM || '.' || CO_PGID || '�z';

		O_DECRYPT_RAW	RAW(512);
		C_STR			VARCHAR(512);

	BEGIN
		
		C_STR := INC_STR;
		
		IF MN_ENCRYPTION_FLAG = 1 THEN
			-- �p�����[�^�����p�X�y�[�X�݂̂̏ꍇ�A�����������͍s�킸�ɏI������
			IF TRIM(INC_STR) IS NULL THEN
				RETURN INC_STR;
			END IF;
			
			-- ����������
			O_DECRYPT_RAW := DBMS_CRYPTO.DECRYPT(INC_STR, CO_DEF_CRYPT, MO_AES_KEY);
			-- RAW�^�f�[�^��VARCHAR2�^�ɕϊ�
			C_STR := UTL_I18N.RAW_TO_CHAR(O_DECRYPT_RAW, 'AL32UTF8');
		END IF;
		
		RETURN C_STR;

	EXCEPTION
		WHEN OTHERS THEN
			RAISE_APPLICATION_ERROR(-20003, SQLERRM || CO_ERRMSG);
	END DECRYPT;


	/****************************************
	||	�p�b�P�[�W��������
	****************************************/
	BEGIN
	DECLARE
	BEGIN
	
		--// �Í����L�[�������RAW�^�ɕϊ����ăC���X�^���X�ϐ��ɕێ�����
		MO_AES_KEY := UTL_I18N.STRING_TO_RAW(RPAD(CO_AES_KEY, 32, '*'), 'AL32UTF8');

		--// �Í����t���O���Z�b�g�i0:�Í������Ȃ��A1�F�Í�������j
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
