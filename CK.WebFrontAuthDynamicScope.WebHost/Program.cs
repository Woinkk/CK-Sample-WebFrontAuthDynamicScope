using CK.WebFrontAuthDynamicScope.App;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CK.WebFrontAuthDynamicScope.WebHost
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Host.CreateDefaultBuilder(args)
                 .UseMonitoring()
                 .ConfigureWebHostDefaults(webBuilder =>
                 {
                     webBuilder
                         .UseKestrel()
                         .UseScopedHttpContext()
                         .UseIISIntegration()
                         .UseStartup<Startup>();
                 })
                .Build()
                .Run();
        }
    }
}
