using Microsoft.IdentityModel.Tokens;

namespace Ecierge.Console.Services.KeyStorage;

public interface IKeyStorage
{
    Task<SecurityKey?> GetKeyAsync(string name, bool isPublic);
    Task<SecurityKey> CreateKeyAsync(string name, string algorithm, int keySize, bool isPublic);
}

