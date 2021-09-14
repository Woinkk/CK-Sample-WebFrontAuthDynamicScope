using CK.AspNet.Auth;
using CK.Auth;
using CK.Core;
using CK.DB.Auth.AuthScope;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using System.Linq;
using CK.SqlServer;
using Microsoft.Extensions.DependencyInjection;

namespace CK.WebFrontAuthDynamicScope.App
{
    public class WebFrontAuthDynamicScopeProvider : IWebFrontAuthDynamicScopeProvider
    {
        readonly CK.DB.User.UserGoogle.AuthScope.Package _googleScope;
        readonly CK.DB.User.UserFacebook.AuthScope.Package _facebookScope;

        public WebFrontAuthDynamicScopeProvider(CK.DB.User.UserGoogle.AuthScope.Package googleScope, CK.DB.User.UserFacebook.AuthScope.Package facebookScope)
        {
            _googleScope = googleScope;
            _facebookScope = facebookScope;
        }

        public async Task<string[]> GetScopesAsync(IActivityMonitor m, WebFrontAuthStartLoginContext context)
        {
            AuthScopeSet? scopeSet = null;
            var ctx = context.HttpContext.RequestServices.GetService<ISqlCallContext>();
            if (context.Scheme == "Google")
            {
                if (context.Current.UnsafeUser.UserId != 0)
                {
                    scopeSet = await _googleScope.ReadScopeSetAsync(ctx, context.Current.UnsafeUser.UserId);
                }
                else
                {
                    scopeSet = await _googleScope.ReadDefaultScopeSetAsync(ctx);
                }
            }
            else if (context.Scheme == "Facebook")
            {
                if (context.Current.UnsafeUser.UserId != 0)
                {
                    scopeSet = await _facebookScope.ReadScopeSetAsync(ctx, context.Current.UnsafeUser.UserId);
                }
                else
                {
                    scopeSet = await _facebookScope.ReadDefaultScopeSetAsync(ctx);
                }

            }
            return scopeSet?.Scopes.Where(s => s.Status == ScopeWARStatus.Waiting).Select(s => s.ScopeName).ToArray() ?? Array.Empty<string>();
        }

        public async Task SetReveivedScopesAsync(IActivityMonitor m, HttpContext c, IAuthenticationInfo current, IReadOnlyList<string> scopes)
        {
            AuthScopeSet? scopeSet = null;
            var ctx = c.RequestServices.GetService<ISqlCallContext>();
            if (current.UnsafeUser.UserId != 0)
            {

                scopeSet = await _facebookScope.ReadScopeSetAsync(ctx, current.User.UserId);

            }
        }
    }
}
