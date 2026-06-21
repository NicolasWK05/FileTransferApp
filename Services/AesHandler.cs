using System.Security.Cryptography;

namespace FileTransferApp.Services;

/// <summary>
/// AES symmetric encryption handler ("AesHandler" per the assignment). Uses
/// AES-GCM rather than plain CBC because GCM provides both confidentiality
/// AND built-in authentication (tamper detection) in a single primitive -
/// exactly the property the assignment's background theory calls out as
/// GCM's advantage over older modes.
/// </summary>
public class AesHandler
{
    private const int KeySizeBytes = 32; // AES-256
    private const int NonceSizeBytes = 12; // GCM standard nonce size
    private const int TagSizeBytes = 16; // GCM standard tag size

    public sealed record EncryptedPayload(byte[] CipherText, byte[] Key, byte[] Nonce, byte[] Tag);

    /// <summary>
    /// Generates a fresh, random, one-time AES-256 key and encrypts
    /// <paramref name="plainText"/> with it using AES-GCM. The plaintext is
    /// expected to already be in memory (read directly from the upload
    /// stream) - it is never written to disk before this call.
    /// </summary>
    public EncryptedPayload Encrypt(byte[] plainText)
    {
        var key = RandomNumberGenerator.GetBytes(KeySizeBytes);
        var nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
        var cipherText = new byte[plainText.Length];
        var tag = new byte[TagSizeBytes];

        using var aesGcm = new AesGcm(key);
        aesGcm.Encrypt(nonce, plainText, cipherText, tag);

        return new EncryptedPayload(cipherText, key, nonce, tag);
    }
}
