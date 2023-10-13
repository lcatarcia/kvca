using Azure.Security.KeyVault.Secrets;
using System;
using System.Threading.Tasks;

namespace KeyVaultCA.Web.KeyVault
{
    public class KeyVaultManager : IKeyVaultManager, IDisposable
    {
        private readonly SecretClient _secretClient;

        public KeyVaultManager(SecretClient secretClient)
        {
            _secretClient = secretClient;
        }

        public void Dispose()
        {
            Console.WriteLine("Ok, it's disposed");
        }

        public async Task<string> GetSecret(string secretName)
        {
            try
            {
                KeyVaultSecret keyVaultSecret = await _secretClient.GetSecretAsync(secretName);
                return keyVaultSecret.Value;
            }
            catch(Exception exc)
            {
                throw;
            }
        }
    }
}
