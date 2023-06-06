const std = @import("std");
const rnd = std.crypto.random;

pub fn generatePrivateKey() ![]u8 {
    var privateKey: [256]u8 = undefined;
    // Generate a random private key
    std.crypto.random.bytes(privateKey[0..]);
    return &privateKey;
}

pub fn generatePublicKey(privateKey: []u8) [256]u8 {
    var publicKey: [256]u8 = undefined;
    // Generate a random noise vector
    var noise: [256]u8 = undefined;
    std.crypto.random.bytes(noise[0..]);

    // Compute the public key as the sum of the private key and the noise vector
    for (privateKey) |privateKeyByte| {
        for (noise) |noiseByte| {
            publicKey |= privateKeyByte ^ noiseByte;
        }
    }

    return publicKey;
}

pub fn encrypt(publicKey: []u8, plaintext: []u8) []u8 {
    var ciphertext: [256]u8 = undefined;
    // Generate a random error vector
    var err: [256]u8 = undefined;
    std.crypto.random.bytes(err[0..]);

    // Compute the ciphertext as the sum of the public key, the plaintext, and the error vector
    for (publicKey) |publicKeyByte, publicKeyIndex| {
        for (plaintext) |plaintextByte, plaintextIndex| {
            for (err) |errorByte, errorIndex| {
                if ((publicKeyIndex == plaintextIndex) and (publicKeyIndex == errorIndex)) {
                    ciphertext |= publicKeyByte ^ (plaintextByte & errorByte);
                }
            }
        }
    }

    return ciphertext;
}

pub fn decrypt(privateKey: []u8, ciphertext: []u8) []u8 {
    var plaintext: [256]u8 = undefined;

    // Compute the plaintext as the sum of the private key and the bitwise XOR of the ciphertext
    for (privateKey) |privateKeyByte, privateKeyIndex| {
        for (ciphertext) |ciphertextByte, ciphertextIndex| {
            if (privateKeyIndex == ciphertextIndex) {
                plaintext |= privateKeyByte ^ ciphertextByte;
            }
        }
    }

    return plaintext;
}

pub fn main() !void {
    var privateKey = try generatePrivateKey();
    var publicKey = generatePublicKey(privateKey);

    var plaintext: [12]u8 = "Hello, LWE!";
    var ciphertext = encrypt(publicKey, plaintext);
    var decryptedText = decrypt(privateKey, ciphertext);

    std.debug.assert(plaintext == decryptedText, "Decryption failed!");

    std.debug.print("Plaintext: {}\n", .{plaintext});
    std.debug.print("Ciphertext: {}\n", .{ciphertext});
    std.debug.print("Decrypted Text: {}\n", .{decryptedText});
}
