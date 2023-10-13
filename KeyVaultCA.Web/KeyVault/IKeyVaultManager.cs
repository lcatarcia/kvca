using System.Threading.Tasks;

namespace KeyVaultCA.Web.KeyVault
{
    public interface IKeyVaultManager
    {
        public Task<string> GetSecret(string secretName);
    }
}
