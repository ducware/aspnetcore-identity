using MimeKit;

namespace Services.Models
{
    public class Message
    {
        public List<MailboxAddress> To { get; set; } = new();
        public string Subject { get; set; } = string.Empty;
        public string Content { get; set; } = string.Empty;

        public Message(IEnumerable<string> to, string subject, string content) 
        { 
            To = new List<MailboxAddress>();
            To.AddRange(to.Select(x => new MailboxAddress("email", x)));
            Subject = subject;
            Content = content;
        }
    }
}
