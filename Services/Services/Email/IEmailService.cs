using Services.Models;

namespace Services.Services.Email
{
    public interface IEmailService
    {
        void SendEmail(Message message);

    }
}
