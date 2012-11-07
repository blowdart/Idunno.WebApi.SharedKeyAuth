using System.ComponentModel.DataAnnotations;

namespace TestReceivingApp.Models
{
    public class Subscriber
    {
        [Required]
        public string Email
        {
            get; 
            set;
        }

        [Required]
        public string Name
        {
            get; 
            set;
        }
    }
}