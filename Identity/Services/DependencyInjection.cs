using Services.Services.Email;

namespace Identity.Services
{
    public static class DependencyInjection
    {
        public static IServiceCollection AddDIServices(this IServiceCollection services)
        {

            services.AddScoped<IEmailService, EmailService>();

            return services;
        }
    }
}
