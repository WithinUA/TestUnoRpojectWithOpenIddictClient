namespace Ecierge.Console;

using global::OpenIddict.Abstractions;
using global::OpenIddict.Client;
using Ecierge.Console.Platforms.WebAssembly;
using global::Uno.Foundation;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

#if __WASM__
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Windows.ApplicationModel.Activation;
#endif

internal struct OpenIddictClientBuilder(SecurityKey? EncryptionKey, SecurityKey? SigningKey)
{
    private static readonly bool platformSupportsDevelopmentCertificates =
        !(RuntimeInformation.IsOSPlatform(OSPlatform.Create("ios")) ||
            RuntimeInformation.IsOSPlatform(OSPlatform.Create("maccatalyst")) ||
            OperatingSystem.IsBrowser());

    internal static async ValueTask<OpenIddictClientBuilder> CreateAsync()
    {
        // TODO: Improve environment resolution dynamically
#if STAGING || PRODUCTION
        var createKeys = true;
#else

        var createKeys = platformSupportsDevelopmentCertificates;
#endif

        if (createKeys)
        {
            return new OpenIddictClientBuilder(null, null);
        }
        else
        {
            var provider = CngProvider.MicrosoftSoftwareKeyStorageProvider;
            var encryptionKey = await GetRsaKeyAsync("Ecierge encryption key", CngKeyUsages.Decryption, provider);
            Console.WriteLine($"Encryption key: {encryptionKey}");
            var signingKey = await GetRsaKeyAsync("Ecierge signing key", CngKeyUsages.Signing, provider);
            Console.WriteLine($"Signing key: {signingKey}");
            return new OpenIddictClientBuilder(encryptionKey, signingKey);
        }
    }


    private static async ValueTask<SecurityKey> GetRsaKeyAsync(string name, CngKeyUsages usages, CngProvider provider)
    {
#pragma warning disable CA2000 // Dispose objects before losing scope
        name = name ?? throw new ArgumentNullException(nameof(name));

        bool isPublic = (usages == CngKeyUsages.Signing || usages == CngKeyUsages.Decryption) ? false : true;
        if (usages != CngKeyUsages.Signing && usages != CngKeyUsages.Decryption)
        {
            throw new ArgumentException("Invalid CngKeyUsages value. Must be either Signing or Decryption.");
        }
        try
        {
            return await new WasmKeyStorage().CreateKeyAsync(name, "RSA", 2048, isPublic);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error creating key: {ex.Message}");
            Console.WriteLine($"Error creating key: {ex.StackTrace}");
            throw;
        }
#pragma warning restore CA2000 // Dispose objects before losing scope
    }

#pragma warning disable CA1506 // Avoid excessive class coupling
    public void ConfigureServices([NotNull] HostBuilderContext context, [NotNull] IServiceCollection services)
    {
        Console.WriteLine($"Configuring OpenIddict client services...");
        var encryptionKey = EncryptionKey;
        var signingKey = SigningKey;
        services.AddOpenIddict()
            // Register the OpenIddict client components.
            .AddClient(options =>
            {
                // Note: this sample uses the authorization code and refresh token
                // flows, but you can enable the other flows if necessary.
                options.AllowAuthorizationCodeFlow()
                       .AllowRefreshTokenFlow();

                // Register the signing and encryption credentials used to protect
                // sensitive data like the state tokens produced by OpenIddict.
                if ((context.HostingEnvironment.IsDevelopment() || context.HostingEnvironment.IsEnvironment(Environments.Development + "Local"))
                && platformSupportsDevelopmentCertificates)
                {
                    options.AddDevelopmentEncryptionCertificate()
                           .AddDevelopmentSigningCertificate();
                }
                else
                {
                    options.AddEncryptionKey(encryptionKey!)
                           .AddSigningKey(signingKey!);
                }


                // Register the System.Net.Http integration and use the identity of the current
                // assembly as a more specific user agent, which can be useful when dealing with
                // providers that use the user agent as a way to throttle requests (e.g Reddit).
                options
                    .UseSystemNetHttp(httpOptions =>
                    {
                        httpOptions.ConfigureHttpClient(client =>
                        {
                            client.DefaultRequestVersion = new Version(2, 0);
#if DEBUG
                            client.Timeout = TimeSpan.FromMinutes(10.0);
#endif
                        });
                    });

                // Add a client registration matching the client application definition in the server project.
                var environmentName = context.HostingEnvironment.EnvironmentName;
#if __WASM__
                var host = WebAssemblyRuntime.InvokeJS("window.location.origin");
#endif
                options.AddRegistration(new OpenIddictClientRegistration
                {
                    Issuer = new Uri("https://localhost:8080"),
                    ProviderName = "<ProviderName>",

                    ClientId = "console",

                    // This sample uses protocol activations with a custom URI scheme to handle callbacks.
                    //
                    // For more information on how to construct private-use URI schemes,
                    // read https://www.rfc-editor.org/rfc/rfc8252#section-7.1 and
                    // https://www.rfc-editor.org/rfc/rfc7595#section-3.8.

#if __WASM__
                    //RedirectUri = serverOptions.RedirectUri,
                    //PostLogoutRedirectUri = serverOptions.PostLogoutRedirectUri,
                    RedirectUri = new Uri("https://localhost:5000/login"),
                    PostLogoutRedirectUri = new Uri("https://localhost:5000/logout"),
#else
                    RedirectUri = new Uri(RedirectUris.getAuthProtocolRedirectUri(RedirectUris.ConsoleScheme, environmentName), UriKind.Absolute),
                    PostLogoutRedirectUri = new Uri(RedirectUris.getHomeProtocolRedirectUri(RedirectUris.ConsoleScheme, environmentName), UriKind.Absolute),
#endif

                    Scopes = {
                        OpenIddictConstants.Scopes.OfflineAccess,
                        OpenIddictConstants.Scopes.Email,
                        OpenIddictConstants.Scopes.Profile,
                        OpenIddictConstants.Scopes.Roles,
                        OpenIddictConstants.Scopes.Phone
                    }
                });
            });
    }
#pragma warning restore CA1506 // Avoid excessive class coupling

    /// <summary>
    /// Resolves the protocol activation using the Windows Runtime APIs, if applicable.
    /// </summary>
    /// <returns>
    /// The <see cref="Uri"/> if the application instance was activated
    /// via a protocol activation, <see langword="null"/> otherwise.
    /// </returns>
    [MethodImpl(MethodImplOptions.NoInlining), SupportedOSPlatform("windows10.0.17763")]
    internal static Uri? GetProtocolActivationUriWithWindowsRuntime()
    {
        return AppInstance.GetActivatedEventArgs() is
            ProtocolActivatedEventArgs args ? args.Uri : null;
    }

    /// <summary>
    /// Resolves the protocol activation from the command line arguments, if applicable.
    /// </summary>
    /// <returns>
    /// The <see cref="Uri"/> if the application instance was activated
    /// via a protocol activation, <see langword="null"/> otherwise.
    /// </returns>
    internal static Uri? GetProtocolActivationUriFromCommandLineArguments(string?[]? arguments) => arguments switch
    {
        // In most cases, the first segment present in the command line arguments contains the path of the
        // executable, but it's technically possible to start an application in a way that the command line
        // arguments will never include the executable path. To support both cases, the URI is extracted
        // from the second segment when 2 segments are present. Otherwise, the first segment is used.
        //
        // For more information, see https://devblogs.microsoft.com/oldnewthing/20060515-07/?p=31203.

        [_, string argument] when Uri.TryCreate(argument, UriKind.Absolute, out Uri? uri) && !uri.IsFile => uri,
        [string argument] when Uri.TryCreate(argument, UriKind.Absolute, out Uri? uri) && !uri.IsFile => uri,

        _ => null
    };

}
