using FileTransferApp.Components;
using FileTransferApp.Services;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddSingleton<AesHandler>();

var fileUploadAppBaseUrl = builder.Configuration["FileUploadAppBaseUrl"]
    ?? throw new InvalidOperationException("Configuration value 'FileUploadAppBaseUrl' not found.");

// Same dev cert used to host both apps locally - reused here so the client
// can pin against it without any manual thumbprint copying.
string trustedCertPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".aspnet/https/Test.pfx");
string trustedCertPassword = "test";

builder.Services.AddHttpClient<FileUploadAppClient>(client =>
{
    client.BaseAddress = new Uri(fileUploadAppBaseUrl);
})
.ConfigurePrimaryHttpMessageHandler(() =>
{
    // Certificate pinning: only the specific certificate we already know the
    // file-upload app uses is accepted - not "any cert the OS happens to
    // trust". This is the actual defense against a man-in-the-middle
    // impersonating the file-upload app's HTTPS endpoint and swapping in its
    // own RSA public key during the key fetch.
    var expectedCert = new X509Certificate2(trustedCertPath, trustedCertPassword);
    var expectedThumbprint = expectedCert.Thumbprint;

    var handler = new HttpClientHandler();
    handler.ServerCertificateCustomValidationCallback = (_, cert, _, _) =>
        cert is not null && string.Equals(cert.Thumbprint, expectedThumbprint, StringComparison.OrdinalIgnoreCase);

    return handler;
});

builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(7068, listenOptions =>
    {
        var cert = new X509Certificate2(trustedCertPath, trustedCertPassword);
        listenOptions.UseHttps(httpsOptions =>
        {
            httpsOptions.ServerCertificate = cert;
            httpsOptions.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
        });
    });

    options.ListenAnyIP(5068);
});

var app = builder.Build();

app.UseHttpsRedirection();
app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
