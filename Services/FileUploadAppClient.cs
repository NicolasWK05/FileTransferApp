using System.Net.Http.Json;

namespace FileTransferApp.Services;

public record PublicKeyResponse(string PublicKeyPem);

public record EncryptedFileUploadRequest(
    string FileName,
    string FileType,
    string EncryptedAesKeyBase64,
    string NonceBase64,
    string TagBase64,
    string CipherTextBase64);

/// <summary>
/// Talks to the file-upload app (exercise 1's app): fetches its RSA public key,
/// then later submits an encrypted file package to it.
/// </summary>
public class FileUploadAppClient(HttpClient http)
{
    public async Task<string> GetPublicKeyPemAsync()
    {
        var response = await http.GetAsync("/rsa/public-key");
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<PublicKeyResponse>();
        return body!.PublicKeyPem;
    }

    public async Task<bool> SendEncryptedFileAsync(EncryptedFileUploadRequest request)
    {
        var response = await http.PostAsJsonAsync("/files/receive-encrypted", request);
        return response.IsSuccessStatusCode;
    }
}
