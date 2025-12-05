// Source:
// https://web.archive.org/web/20250331235951/https://bitwarden.com/crypto.html
// Modified: removed try/catch blocks to allow errors to propagate for external handling



const encTypes = {
	AesCbc256_B64: 0,
	AesCbc128_HmacSha256_B64: 1,
	AesCbc256_HmacSha256_B64: 2,
	Rsa2048_OaepSha256_B64: 3,
	Rsa2048_OaepSha1_B64: 4,
	Rsa2048_OaepSha256_HmacSha256_B64: 5,
	Rsa2048_OaepSha1_HmacSha256_B64: 6,
}

// Object Classes

class Cipher {
	constructor(encType, iv, ct, mac) {
		if (!arguments.length) {
			this.encType = null
			this.iv = null
			this.ct = null
			this.mac = null
			this.string = null
			return
		}

		this.encType = encType
		this.iv = iv
		this.ct = ct
		this.string = encType + '.' + iv.b64 + '|' + ct.b64

		this.mac = null
		if (mac) {
			this.mac = mac
			this.string += '|' + mac.b64
		}
	}
}

class ByteData {
	constructor(buf) {
		if (!arguments.length) {
			this.arr = null
			this.b64 = null
			return
		}

		this.arr = new Uint8Array(buf)
		this.b64 = toB64(buf)
	}
}

class SymmetricCryptoKey {
	constructor(buf) {
		if (!arguments.length) {
			this.key = new ByteData()
			this.encKey = new ByteData()
			this.macKey = new ByteData()
			return
		}

		this.key = new ByteData(buf)

		// First half
		const encKey = this.key.arr.slice(0, this.key.arr.length / 2).buffer
		this.encKey = new ByteData(encKey)

		// Second half
		const macKey = this.key.arr.slice(this.key.arr.length / 2).buffer
		this.macKey = new ByteData(macKey)
	}
}

// Helpers

function fromUtf8(str) {
	const strUtf8 = unescape(encodeURIComponent(str))
	const bytes = new Uint8Array(strUtf8.length)
	for (let i = 0; i < strUtf8.length; i++) {
		bytes[i] = strUtf8.charCodeAt(i)
	}
	return bytes.buffer
}

function toUtf8(buf) {
	const bytes = new Uint8Array(buf)
	const encodedString = String.fromCharCode.apply(null, bytes)
	return decodeURIComponent(escape(encodedString))
}

function toB64(buf) {
	let binary = ''
	const bytes = new Uint8Array(buf)
	for (let i = 0; i < bytes.byteLength; i++) {
		binary += String.fromCharCode(bytes[i])
	}
	return window.btoa(binary)
}

// Crypto

async function pbkdf2(password, salt, iterations, length) {
	const importAlg = {
		name: 'PBKDF2',
	}

	const deriveAlg = {
		name: 'PBKDF2',
		salt: salt,
		iterations: iterations,
		hash: { name: 'SHA-256' },
	}

	const aesOptions = {
		name: 'AES-CBC',
		length: length,
	}

	const importedKey = await window.crypto.subtle.importKey('raw', password, importAlg, false, ['deriveKey'])
	const derivedKey = await window.crypto.subtle.deriveKey(deriveAlg, importedKey, aesOptions, true, [
		'encrypt',
	])
	const exportedKey = await window.crypto.subtle.exportKey('raw', derivedKey)
	return new ByteData(exportedKey)
}

async function aesDecrypt(cipher, encKey, macKey) {
	const keyOptions = {
		name: 'AES-CBC',
	}

	const decOptions = {
		name: 'AES-CBC',
		iv: cipher.iv.arr.buffer,
	}

	const checkMac = cipher.encType != encTypes.AesCbc256_B64
	if (checkMac) {
		if (!macKey) {
			throw 'MAC key not provided.'
		}
		const dataForMac = buildDataForMac(cipher.iv.arr, cipher.ct.arr)
		const macBuffer = await computeMac(dataForMac.buffer, macKey.arr.buffer)
		const macsMatch = await macsEqual(cipher.mac.arr.buffer, macBuffer, macKey.arr.buffer)
		if (!macsMatch) {
			throw 'MAC check failed.'
		}
		const importedKey = await window.crypto.subtle.importKey('raw', encKey.arr.buffer, keyOptions, false, [
			'decrypt',
		])
		return window.crypto.subtle.decrypt(decOptions, importedKey, cipher.ct.arr.buffer)
	}
}

async function computeMac(data, key) {
	const alg = {
		name: 'HMAC',
		hash: { name: 'SHA-256' },
	}
	const importedKey = await window.crypto.subtle.importKey('raw', key, alg, false, ['sign'])
	return window.crypto.subtle.sign(alg, importedKey, data)
}

async function macsEqual(mac1Data, mac2Data, key) {
	const alg = {
		name: 'HMAC',
		hash: { name: 'SHA-256' },
	}

	const importedMacKey = await window.crypto.subtle.importKey('raw', key, alg, false, ['sign'])
	const mac1 = await window.crypto.subtle.sign(alg, importedMacKey, mac1Data)
	const mac2 = await window.crypto.subtle.sign(alg, importedMacKey, mac2Data)

	if (mac1.byteLength !== mac2.byteLength) {
		return false
	}

	const arr1 = new Uint8Array(mac1)
	const arr2 = new Uint8Array(mac2)

	for (let i = 0; i < arr2.length; i++) {
		if (arr1[i] !== arr2[i]) {
			return false
		}
	}

	return true
}

function buildDataForMac(ivArr, ctArr) {
	const dataForMac = new Uint8Array(ivArr.length + ctArr.length)
	dataForMac.set(ivArr, 0)
	dataForMac.set(ctArr, ivArr.length)
	return dataForMac
}

async function stretchKey(key) {
	const newKey = new Uint8Array(64)
	newKey.set(await hkdfExpand(key, new Uint8Array(fromUtf8('enc')), 32))
	newKey.set(await hkdfExpand(key, new Uint8Array(fromUtf8('mac')), 32), 32)
	return new SymmetricCryptoKey(newKey.buffer)
}

// ref: https://tools.ietf.org/html/rfc5869
async function hkdfExpand(prk, info, size) {
	const alg = {
		name: 'HMAC',
		hash: { name: 'SHA-256' },
	}
	const importedKey = await window.crypto.subtle.importKey('raw', prk, alg, false, ['sign'])
	const hashLen = 32 // sha256
	const okm = new Uint8Array(size)
	let previousT = new Uint8Array(0)
	const n = Math.ceil(size / hashLen)
	for (let i = 0; i < n; i++) {
		const t = new Uint8Array(previousT.length + info.length + 1)
		t.set(previousT)
		t.set(info, previousT.length)
		t.set([i + 1], t.length - 1)
		previousT = new Uint8Array(await window.crypto.subtle.sign(alg, importedKey, t.buffer))
		okm.set(previousT, i * hashLen)
	}
	return okm
}
