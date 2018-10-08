using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(BennetVellaSecureSoftware.Startup))]
namespace BennetVellaSecureSoftware
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
