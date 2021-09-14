using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CK.AspNet.Auth;
using CK.Core;
using System.Security.Claims;
using CK.Auth;
using CK.DB.Actor;
using CK.SqlServer;
using System.Collections.ObjectModel;

namespace CK.WebFrontAuthDynamicScope.App

{
    public class Startup
    {
        readonly IConfiguration _configuration;
        readonly IWebHostEnvironment _hostingEnvironment;
        readonly IActivityMonitor _startupMonitor;

        public Startup(IConfiguration configuration, IWebHostEnvironment env)
        {
            _startupMonitor = new ActivityMonitor($"App {env.ApplicationName}/{env.EnvironmentName} on {Environment.MachineName}/{Environment.UserName}.");
            _configuration = configuration;
            _hostingEnvironment = env;
        }

        private void CheckSameSite(HttpContext httpContext, CookieOptions options)
        {
            if (options.SameSite == SameSiteMode.None)
            {
                var userAgent = httpContext.Request.Headers["User-Agent"].ToString();
                // TODO: Use your User Agent library of choice here.
                if (!DisallowsSameSiteNone(userAgent))
                {
                    // For .NET Core < 3.1 set SameSite = (SameSiteMode)(-1)
                    options.SameSite = SameSiteMode.Unspecified;
                }
            }
        }

        public static bool DisallowsSameSiteNone(string userAgent)
        {
            if (string.IsNullOrEmpty(userAgent))
            {
                return false;
            }

            // Cover all iOS based browsers here. This includes:
            // - Safari on iOS 12 for iPhone, iPod Touch, iPad
            // - WkWebview on iOS 12 for iPhone, iPod Touch, iPad
            // - Chrome on iOS 12 for iPhone, iPod Touch, iPad
            // All of which are broken by SameSite=None, because they use the iOS networking stack
            if (userAgent.Contains("CPU iPhone OS 12") || userAgent.Contains("iPad; CPU OS 12"))
            {
                return true;
            }

            // Cover Mac OS X based browsers that use the Mac OS networking stack. This includes:
            // - Safari on Mac OS X.
            // This does not include:
            // - Chrome on Mac OS X
            // Because they do not use the Mac OS networking stack.
            if (userAgent.Contains("Macintosh; Intel Mac OS X 10_14") &&
                userAgent.Contains("Version/") && userAgent.Contains("Safari"))
            {
                return true;
            }

            // Cover Chrome 50-69, because some versions are broken by SameSite=None, 
            // and none in this range require it.
            // Note: this covers some pre-Chromium Edge versions, 
            // but pre-Chromium Edge does not require SameSite=None.
            if (userAgent.Contains("Chrome/5") || userAgent.Contains("Chrome/6"))
            {
                return true;
            }

            return false;
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // The entry point assembly contains the generated code.
            services.AddCKDatabase(_startupMonitor, System.Reflection.Assembly.GetEntryAssembly());

            //Configured cookie policy due to correlation fail when trying to authenticate with oidc (review that)
            // Que veut dire ce "(review that)" ?
            services.Configure<CookiePolicyOptions>(options =>
            {
                options.MinimumSameSitePolicy = SameSiteMode.Unspecified;
                options.OnAppendCookie = cookieContext =>
                    CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);
                options.OnDeleteCookie = cookieContext =>
                    CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);
            });

            // By specifying the defaultScheme here, the https://github.com/Invenietis/CK-AspNet-Auth/blob/master/CK.AspNet.Auth/WebFrontAuthHandler.cs#L490-L502
            // HandleAuthenticateAsync() method is called: the Request.User ClaimsPrincipal is built based on the IAuthenticationInfo.
            services
                .AddAuthentication(defaultScheme: WebFrontAuthOptions.OnlyAuthenticationScheme)
                .AddGoogle("Google", o =>
                {
                    o.ClientId = _configuration["Authentication:Google:ClientId"];
                    o.ClientSecret = _configuration["Authentication:Google:ClientSecret"];

                    o.Events.OnRemoteFailure = f => f.WebFrontAuthRemoteFailureAsync();

                    // Google package filters the original claims to standard ones, but "email_verified" and "pictures" are lost.
                    // This is why here, we intercept the early ticket creation and save the fields in the AuthenticationProperties.Parameters.
                    // (Parameters are a simple Dictionary<string,object> that is transient, as opposed to the Items that are persisted and follow
                    // the whole authentication flow).
                    o.Events.OnCreatingTicket = c =>
                    {
                        //c.Properties.Parameters["picture"] = (string)c.User["picture"];
                        //c.Properties.Parameters["verified_email"] = (string)c.User["verified_email"];
                        return Task.CompletedTask;
                    };


                    o.Events.OnTicketReceived = c => c.WebFrontAuthRemoteAuthenticateAsync<IUserGoogleInfo>(payload =>
                    {
                        payload.GoogleAccountId = c.Principal.FindFirst(ClaimTypes.NameIdentifier).Value;
                        payload.EMail = c.Principal.FindFirst(ClaimTypes.Email).Value;
                        payload.FirstName = c.Principal.FindFirst(ClaimTypes.GivenName)?.Value;
                        payload.LastName = c.Principal.FindFirst(ClaimTypes.Surname)?.Value;
                        payload.UserName = c.Principal.FindFirst(ClaimTypes.Name)?.Value;
                        payload.EMailVerified = (string)c.Properties.Parameters.GetValueWithDefault("verified_email", null) == "True";

                    });
                })
                .AddFacebook("Facebook", o =>
                {
                    o.AppId = _configuration["Authentication:Facebook:ClientId"];
                    o.AppSecret = _configuration["Authentication:Facebook:ClientSecret"];
                    o.Events.OnRemoteFailure = f => f.WebFrontAuthRemoteFailureAsync();

                    o.Events.OnTicketReceived = c => c.WebFrontAuthRemoteAuthenticateAsync<IUserFacebookInfo>(payload =>
                    {
                        payload.FacebookAccountId = c.Principal.FindFirst(ClaimTypes.NameIdentifier).Value;
                        payload.UserName = c.Principal.FindFirst(ClaimTypes.Name)?.Value;
                        // User can decline the "email" scope.
                        payload.EMail = c.Principal.FindFirst(ClaimTypes.Email)?.Value;
                        payload.FirstName = c.Principal.FindFirst(ClaimTypes.GivenName).Value;
                        payload.LastName = c.Principal.FindFirst(ClaimTypes.Surname).Value;

                        IWebFrontAuthDynamicScopeProvider dynamicScope = c.HttpContext.RequestServices.GetRequiredService<IWebFrontAuthDynamicScopeProvider>();

                        ISqlCallContext ctx = c.HttpContext.RequestServices.GetRequiredService<ISqlCallContext>();

                        IAuthenticationTypeSystem authType = c.HttpContext.RequestServices.GetRequiredService<IAuthenticationTypeSystem>();

                        IUserInfo userInfo = authType.UserInfo.Create(1004, payload.UserName);

                        IAuthenticationInfo authInfo = authType.AuthenticationInfo.Create(userInfo);

                        Task scopes = dynamicScope.SetReveivedScopesAsync(_startupMonitor, c.HttpContext, authInfo, o.Scope.ToList());
                    });

                })
                .AddWebFrontAuth(options =>
                {
                    options.ExpireTimeSpan = TimeSpan.FromDays(1);
                });

            services.AddCors();
            services.AddControllers();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (_hostingEnvironment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            app.UseGuardRequestMonitor();

            app.UseRouting();

            app.UseCors(c =>
               c.SetIsOriginAllowed(host => true)
                .AllowAnyMethod()
                .AllowAnyHeader()
                .AllowCredentials());

            app.UseCookiePolicy();
            app.UseAuthentication();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
