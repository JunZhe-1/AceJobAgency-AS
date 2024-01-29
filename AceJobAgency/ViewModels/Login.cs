using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace AceJobAgency.viewModels
{
    [Keyless]

    public class Login
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email address")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}
