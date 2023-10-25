using System.IdentityModel.Tokens.Jwt;

namespace Identity.Middlewares
{
    public class ValidateJwtTokenMiddleware
    {
        private readonly RequestDelegate _next;

        public ValidateJwtTokenMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            string token = context.Request.Headers["Authorization"].SingleOrDefault()?.Split(" ").Last();

            if (token != null)
            {
                try
                {
                    var handler = new JwtSecurityTokenHandler();
                    var jwtToken = handler.ReadToken(token) as JwtSecurityToken;

                    if (jwtToken != null && jwtToken.ValidTo <= DateTime.UtcNow)
                    {
                        context.Response.StatusCode = 401;  // Unauthorized
                        return;
                    }
                }
                catch
                {
                    context.Response.StatusCode = 401;  // Unauthorized
                    return;
                }
            }

            await _next.Invoke(context);
        }
    }
}
