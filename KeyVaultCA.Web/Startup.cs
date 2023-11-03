using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using KeyVaultCa.Core;
using KeyVaultCA.Web.Auth;
using KeyVaultCA.Web.KeyVault;
using KeyVaultCA.Web.RoleManager;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Azure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.OpenApi.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace KeyVaultCA.Web
{
	public class Startup
	{
		ILogger<Startup> logger;
		public Startup(IConfiguration configuration)
		{
			Configuration = configuration;
			ILoggerFactory loggerFactory = LoggerFactory.Create(builder =>
			{
				builder.AddConsole();
				builder.AddDebug();
			});
			logger = loggerFactory.CreateLogger<Startup>();
		}

		public IConfiguration Configuration { get; }

		// This method gets called by the runtime. Use this method to add services to the container.
		public void ConfigureServices(IServiceCollection services)
		{
			services.AddApplicationInsightsTelemetry();

			EstConfiguration estConfig = Configuration.GetSection("KeyVault").Get<EstConfiguration>();
			services.AddSingleton(estConfig);

			AuthConfiguration estAuth = Configuration.GetSection("EstAuthentication").Get<AuthConfiguration>();
			services.AddSingleton(estAuth);

			Caller caller = new();
			services.AddSingleton(caller);

			RoleManagerConfiguration roleManagerConfig = Configuration.GetSection("UserFlow").Get<RoleManagerConfiguration>();
			services.AddSingleton(roleManagerConfig);

			DefaultAzureCredential azureCredential = new DefaultAzureCredential();
			services.AddSingleton(azureCredential);
			services.AddSingleton<KeyVaultServiceClient>();
			services.AddSingleton<IKeyVaultCertificateProvider, KeyVaultCertificateProvider>();

			services.AddAzureClients(azureClientFactoryBuilder =>
			{
				azureClientFactoryBuilder.AddSecretClient(
					Configuration.GetSection("KeyVault")
					);
			});
			services.AddSingleton<IKeyVaultManager, KeyVaultManager>();
			var secretManager =

			services.AddControllersWithViews();

			services.AddScoped<IUserService, UserService>();

			if (estAuth.AuthMode == AuthMode.Basic)
			{
				services.AddAuthentication("BasicAuthentication")
					.AddScheme<AuthenticationSchemeOptions, BasicAuthenticationHandler>("BasicAuthentication", null);
			}
			else if (estAuth.AuthMode == AuthMode.x509)
			{
				services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
				   .AddCertificate(async options =>
				   {
					   var trustedCAs = new List<X509Certificate2>();
					   var currentDirectory = AppContext.BaseDirectory;
					   //var currentDirectory = Directory.GetCurrentDirectory();
					   var trustedCADir = Path.Combine(currentDirectory, @"TrustedCAs");

					   logger.LogTrace("directory: {0}", trustedCADir);


#if DEBUG
					   foreach (string file in Directory.EnumerateFiles(trustedCADir, "*.cer"))
					   {
						   string contents = File.ReadAllText(file);
						   trustedCAs.Add(X509Certificate2.CreateFromPem(contents));
					   }
#else
                       // secret fetched from KeyVault. It contains the thumbprint of the certificate
                       SecretClient secretClient = new SecretClient(
                         new Uri(Configuration.GetSection("KeyVault:KeyVaultUrl").Value),
                         azureCredential);
                       string secretValue = string.Empty;
                       using (KeyVaultManager secretManager = new KeyVaultManager(secretClient))
                       {
                           string secretName = "CertThumbprint";
                           secretValue = await secretManager.GetSecret(secretName);
                       }

                       using (X509Store certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser))
                       {
                           certStore.Open(OpenFlags.ReadOnly);

                           X509Certificate2Collection certCollection = certStore.Certificates.Find(
                                                       X509FindType.FindByThumbprint,
                                                       secretValue,
                                                       false);
                           // Get the first cert with the thumbprint (should be only one)
                           X509Certificate2 signingCert = certCollection.OfType<X509Certificate2>().FirstOrDefault();

                           //if (signingCert is null)
                           //    throw new Exception($"Certificate with thumbprint {options.SigningCertificateThumbprint} was not found");

                           trustedCAs.Add(signingCert);
                       }

#endif

					   options.CustomTrustStore.AddRange(new X509Certificate2Collection(trustedCAs.ToArray()));

					   // Azure KeyVault does not support this
					   options.RevocationMode = X509RevocationMode.NoCheck;
					   options.ChainTrustValidationMode = X509ChainTrustMode.CustomRootTrust;

					   options.Events = new CertificateAuthenticationEvents
					   {
						   OnCertificateValidated = context =>
						   {
							   var claims = new[]
							   {
										new Claim(
											ClaimTypes.NameIdentifier,
											context.ClientCertificate.Subject,
											ClaimValueTypes.String,
											context.Options.ClaimsIssuer),
										new Claim(
											ClaimTypes.Name,
											context.ClientCertificate.Subject,
											ClaimValueTypes.String,
											context.Options.ClaimsIssuer)
							   };

							   context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
							   context.Success();

							   return Task.CompletedTask;
						   }
					   };
				   })
				   .AddCertificateCache();

				services.AddCertificateForwarding(options =>
				{
					options.CertificateHeader = "X-ARR-ClientCert";
				});

				services.Configure<ForwardedHeadersOptions>(options =>
				{
					options.ForwardedHeaders = ForwardedHeaders.XForwardedProto;
					options.ForwardedProtoHeaderName = "X-Forwarded-Proto";
				});
			}

			services.AddSwaggerGen(c =>
			{
				c.EnableAnnotations();
				c.SwaggerDoc("v1", new OpenApiInfo { Title = "KeyVaultCA Create and Sign", Version = "v1" });
			});

		}

		// This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
		public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
		{
			if (env.IsDevelopment())
			{
				app.UseDeveloperExceptionPage();
			}

			app.UseStaticFiles();

			app.UseSwagger();
			app.UseSwaggerUI(
				c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "KeyVaultCA.Web v1")
				);

			app.UseRouting();
			app.UseCertificateForwarding();
			app.UseForwardedHeaders();
			app.UseAuthentication();
			app.UseAuthorization();
			app.UseEndpoints(endpoints =>
			{
				endpoints.MapControllerRoute(
					name: "default",
					pattern: "{controller=Home}/{action=Index}");
			});
			//app.UseEndpoints(endpoints =>
			//{
			//    endpoints.MapControllers();
			//});
		}
	}
}
