using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace AspNetCore.SecurityHeaders.Configuration.SecurityHeaders
{
    public static class IApplicationBuilderExtensions
	{
		public static void UseSecurityHeaders(this IApplicationBuilder app)
		{
			app.UseMiddleware<SecurityHeadersMiddleware>();
		}
	}

    public class SecurityHeadersMiddleware
    {
        private readonly RequestDelegate _next;

		public SecurityHeadersMiddleware(RequestDelegate next)
		{
			_next = next;
		}

		public async Task Invoke(HttpContext context)
		{
			var csp = new StringBuilder();
			
			csp.Append("default-src 'self' https://cdnjs.cloudflare.com https://stackpath.bootstrapcdn.com;");
			csp.Append("style-src 'self' https://stackpath.bootstrapcdn.com;");
			csp.Append("frame-ancestors 'none';");
			
			context.Response.Headers.Add("Content-Security-Policy", csp.ToString());
			context.Response.Headers.Add("X-Frame-Options", "DENY");
			context.Response.Headers.Add("Feature-Policy", "camera 'none'");
			context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
			context.Response.Headers.Add("Referrer-Policy", "no-referrer");
			context.Response.Headers.Add("Cache-Control", "public, max-age=3600");

			await _next(context);
		}
    }
}