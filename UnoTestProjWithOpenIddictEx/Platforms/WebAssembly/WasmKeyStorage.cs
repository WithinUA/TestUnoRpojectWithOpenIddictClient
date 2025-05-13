namespace Ecierge.Console.Platforms.WebAssembly;

using System;
using System.Text.Json;
using Ecierge.Console.Services.KeyStorage;
using Microsoft.IdentityModel.Tokens;
using Uno.Foundation;

public class WasmKeyStorage : IKeyStorage
{
    public async Task<SecurityKey> CreateKeyAsync(string name, string algorithm, int keySize, bool isPublic)
        => await GetKeyAsync(name, isPublic).ConfigureAwait(false);

    public async Task<SecurityKey?> GetKeyAsync(string name, bool isPublic)
    {
        try
        {
            string declareFunctionScript = """
                window.getKeyForCSharp = async function (name){
                    try {
                        let key = await KeyStore.getKey(name);
                        KeyStore.clearKey(name)
                        return key;
                    } catch (e) {
                        console.error(e.message);
                        throw e;
                    }
                };
            """;
            WebAssemblyRuntime.InvokeJS(declareFunctionScript);
            var jwkJson = await WebAssemblyRuntime.InvokeAsync($$"""( async () => { return await getKeyForCSharp('{{name}}') })()""");
            var deserializeKey = JsonSerializer.Deserialize<JsonWebKey>(jwkJson);
            return deserializeKey;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error creating key: {ex.Message}");
            throw;
        }
    }
}
