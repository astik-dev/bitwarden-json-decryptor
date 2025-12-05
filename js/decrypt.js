/**
 * @param {object} json 
 * @returns {boolean}
 */
function validateBitwardenJson(json) {
	return (
		json.encrypted === true &&
		json.passwordProtected === true &&
		typeof json.salt === "string" &&
		json.kdfType === 0 &&
		typeof json.kdfIterations === "number" &&
		typeof json.encKeyValidation_DO_NOT_EDIT === "string" &&
		json.encKeyValidation_DO_NOT_EDIT.startsWith("2") &&
		typeof json.data === "string" &&
		json.data.startsWith("2")
	);
}

/**
 * @param {string} b64 
 * @returns {ArrayBuffer}
 */
function fromB64(b64) {
	const binary = window.atob(b64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes.buffer;
}

/**
 * @param {string} cipherString - "encType.ivB64|ctB64|macB64"
 * @returns {Cipher}
 */
function parseCipherString(cipherString) {

	const firstDot = cipherString.indexOf(".");
	const encType = Number(cipherString.slice(0, firstDot));

	const rest = cipherString.slice(firstDot + 1);
	const [ ivB64, ctB64, macB64 ] = rest.split("|");
	const ivBD = new ByteData(fromB64(ivB64));
	const ctBD = new ByteData(fromB64(ctB64));
	const macBD = new ByteData(fromB64(macB64));

	return new Cipher(encType, ivBD, ctBD, macBD);
}

/**
 * @param {string} json 
 * @param {string} masterPassword 
 * @returns {string | undefined}
 */
async function decryptBitwardenJson(json, masterPassword) {

	const jsonObj = JSON.parse(json);

	const isValidJsonObj = validateBitwardenJson(jsonObj);
	if (isValidJsonObj === false) {
		throw new Error("Invalid JSON");
	}

	const saltBuf = fromUtf8(jsonObj.salt);
	const passwordBuf = fromUtf8(masterPassword);

	const masterKeyBD =
		await pbkdf2(passwordBuf, saltBuf, jsonObj.kdfIterations, 256);

	const stretched = await stretchKey(masterKeyBD.arr.buffer);

	const validationCipher = parseCipherString(jsonObj.encKeyValidation_DO_NOT_EDIT);
	const decryptedValidation =
		await aesDecrypt(validationCipher, stretched.encKey, stretched.macKey);

	if (decryptedValidation) {
		const dataCipher = parseCipherString(jsonObj.data);
		const decryptedData =
			await aesDecrypt(dataCipher, stretched.encKey, stretched.macKey);
		if (decryptedData) {
			return toUtf8(decryptedData);
		}
	}
}
