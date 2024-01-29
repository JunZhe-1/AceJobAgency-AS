using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace AceJobAgency.viewModels
{
    [Keyless]

    public class ChangePWD
    {

        [Required]
        [DataType(DataType.Password)]
        public string Current_Password { get; set; }
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Password and confirmation password do not match")]
        public string ConfirmPassword { get; set; }

    }
}
