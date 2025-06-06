namespace Ecierge.Console.Platforms.WebAssembly;


using System;
using System.Runtime.InteropServices.JavaScript;
using System.Text.Json;
using Ecierge.Console.Services.KeyStorage;
using Microsoft.IdentityModel.Tokens;
using Uno.Foundation;

public partial class WasmKeyStorage : IKeyStorage
{
    public async Task<SecurityKey> CreateKeyAsync(string name, string algorithm, int keySize, bool isPublic)
        => await GetKeyAsync(name, isPublic).ConfigureAwait(false);

    private const string GetKeyFunctionName = "globalThis.tryGetRsaKey";

    [JSImport(GetKeyFunctionName)]
    public static partial Task<string> GetKeyForCSharp(string name);


    static WasmKeyStorage()
    {
        try
        {
            // Register the JavaScript function to be called from C#
            WebAssemblyRuntime.InvokeJS($$"""
            {
                {{GetKeyFunctionName}} = async function(name) {
                    try {
                        let key = await KeyStore.getKey(name);
                        return key;
                    } catch (e) {
                        console.error('KeyStore.getKey error:', e);
                        return null;
                    }
                };
            };
            """);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error registering JavaScript function: {ex.Message}");
        }
    }

    public async Task<SecurityKey?> GetKeyAsync(string name, bool isPublic)
    {
        try
        {
            //Debugger.Break();
            var jwkJson = await GetKeyForCSharp(name);

            if (string.IsNullOrEmpty(jwkJson))
            {
                Console.WriteLine($"No key found with name: {name}");
                return null;
            }

            return JsonSerializer.Deserialize<JsonWebKey>(jwkJson);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error creating key: {ex.Message}");
            Console.WriteLine($"Error creating key: {ex.StackTrace}");
            throw;
        }
    }
}
