using System;
using System.Collections.Generic;
using System.Text;

namespace CK.WebFrontAuthDynamicScope.App
{
    /// <summary>
    /// We need to use "profile" scope.
    /// </summary>
    public interface IUserGoogleInfo : CK.DB.User.UserGoogle.IUserGoogleInfo
    {
        string FirstName { get; set; }
        string LastName { get; set; }
        string UserName { get; set; }
    }

}
