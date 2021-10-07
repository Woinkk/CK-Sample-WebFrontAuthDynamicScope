using System;
using System.Collections.Generic;
using System.Text;

namespace CK.WebFrontAuthDynamicScope.App
{
    public interface IUserFacebookInfo : CK.DB.User.UserFacebook.IUserFacebookInfo
    {
        string FirstName { get; set; }
        string LastName { get; set; }
        string UserName { get; set; }
    }

}
