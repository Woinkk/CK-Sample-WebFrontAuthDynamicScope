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
using Newtonsoft.Json.Linq;
using CK.WebFrontAuthDynamicScope.App.Services;
using CK.DB.User.UserGoogle;

namespace CK.WebFrontAuthDynamicScope.App

{
    public class Startup
    {
        readonly IConfiguration _configuration;
        readonly IWebHostEnvironment _hostingEnvironment;
        readonly IActivityMonitor _startupMonitor;
        //readonly CheckScopesServices _checkScopesServices;

        public Startup(IConfiguration configuration, IWebHostEnvironment env )
        {
            _startupMonitor = new ActivityMonitor($"App {env.ApplicationName}/{env.EnvironmentName} on {Environment.MachineName}/{Environment.UserName}.");
            _configuration = configuration;
            _hostingEnvironment = env;
            //_checkScopesServices = checkScopesServices;
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

            services.AddHttpClient();

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
                    o.SaveTokens = true;

                    o.Events.OnRemoteFailure = f =>
                    {
                        return f.WebFrontAuthOnRemoteFailureAsync( setUnsafeLevel: true );
                    };

                    o.Events.OnCreatingTicket = c =>
                    {
                        return Task.CompletedTask;
                    };

                    // Google is weird. When we do not accept any scopes google send back an access denied so for that case we have to
                    // check scopes on the event OnAccessDenied and keep the current authentication if we are already authenticated.
                    o.Events.OnAccessDenied = async ( c ) =>
                    {
                        var authInfo = c.GetTicketAuthenticationInfo();
                        if( authInfo.Level != AuthLevel.None )
                        {
                            string? accessToken = null;
                            // Get the service meant to check and update scopes for a user.
                            CheckScopesServices checkScopesServices = c.HttpContext.RequestServices.GetRequiredService<CheckScopesServices>();
                            await checkScopesServices.CheckAndUpdateGoogleScopesAsync( _startupMonitor, c.HttpContext, authInfo, accessToken );
                        }
                        await c.WebFrontAuthOnAccessDeniedAsync();
                    };


                    o.Events.OnTicketReceived = async c => 
                    {
                        await c.WebFrontAuthOnTicketReceivedAsync<IUserGoogleInfo>( payload =>
                        {
                            payload.GoogleAccountId = c.Principal.FindFirst( ClaimTypes.NameIdentifier ).Value;
                            payload.FirstName = c.Principal.FindFirst( ClaimTypes.GivenName ).Value;
                            payload.LastName = c.Principal.FindFirst( ClaimTypes.Surname ).Value;
                            payload.UserName = c.Principal.FindFirst( ClaimTypes.Name ).Value;
                        });

                        // Get the current auth info.
                        var authInfo = c.HttpContext.GetAuthenticationInfo();
                        if( authInfo.Level != AuthLevel.None )
                        {
                            string accessToken = c.Properties.Items[".Token.access_token"];
                            // Get the service meant to check and update scopes for a user.
                            CheckScopesServices checkScopesServices = c.HttpContext.RequestServices.GetRequiredService<CheckScopesServices>();
                            await checkScopesServices.CheckAndUpdateGoogleScopesAsync( _startupMonitor, c.HttpContext, authInfo, accessToken );
                        }
                    };
                })
                .AddFacebook("Facebook", o =>
                {
                    o.AppId = _configuration["Authentication:Facebook:ClientId"];
                    o.AppSecret = _configuration["Authentication:Facebook:ClientSecret"];
                    o.Events.OnRemoteFailure = f => f.WebFrontAuthOnRemoteFailureAsync();
                    o.SaveTokens = true;

                    o.Events.OnTicketReceived = async c =>
                    {
                        await c.WebFrontAuthOnTicketReceivedAsync<IUserFacebookInfo>( payload =>
                        {
                             payload.FacebookAccountId = c.Principal.FindFirst( ClaimTypes.NameIdentifier ).Value;
                             payload.UserName = c.Principal.FindFirst( ClaimTypes.Name ).Value;
                             payload.FirstName = c.Principal.FindFirst( ClaimTypes.GivenName ).Value;
                             payload.LastName = c.Principal.FindFirst( ClaimTypes.Surname ).Value;
                        } );

                        // Get the current auth info.
                        var authInfo = c.HttpContext.GetAuthenticationInfo();
                        if( authInfo.Level != AuthLevel.None )
                        {
                            string accessToken = c.Properties.Items[".Token.access_token"];

                            // Get the service meant to check and update scopes for a user.
                            CheckScopesServices checkScopesServices = c.HttpContext.RequestServices.GetRequiredService<CheckScopesServices>();
                            await checkScopesServices.CheckAndUpdateFacebookScopesAsync( _startupMonitor, c.HttpContext ,authInfo, accessToken );
                        }
                    };
                })
                .AddWebFrontAuth(options =>
                {
                    options.ExpireTimeSpan = TimeSpan.FromDays(1);
                    options.SchemesCriticalTimeSpan = new Dictionary<string, TimeSpan>
                    {
                        { "Basic", new TimeSpan( 0, 5, 0 ) },
                        { "Google", new TimeSpan( 0, 5, 0 ) },
                        { "Facebook", new TimeSpan( 0, 5, 0 ) }
                    };
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
