using System;
using System.ComponentModel.DataAnnotations;

namespace WebApplication3.ViewModels
{
    public class Register
    {
        [Key]
        public int UserId { get; set; }

        [Required(ErrorMessage = "First Name is required")]
        [RegularExpression("^[^<>]+$", ErrorMessage = "Invalid characters. Please remove < and >.")]
        public string First_Name { get; set; }

        [Required(ErrorMessage = "Last Name is required")]
        [RegularExpression("^[^<>]+$", ErrorMessage = "Invalid characters. Please remove < and >.")]
        public string Last_Name { get; set; }

        [Required(ErrorMessage = "Gender is required")]
        public string Gender { get; set; }

        [Required(ErrorMessage = "NRIC is required")]
        [RegularExpression("^[TtSs]\\d{7}[A-Za-z]$", ErrorMessage = "Invalid NRIC format.")]
        public string NRIC { get; set; }

        [Required(ErrorMessage = "Email is required")]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Password and confirmation password do not match")]
        public string ConfirmPassword { get; set; }

        [Required(ErrorMessage = "DateOfBirth is required")]
        [DataType(DataType.Date)]
        public DateTime DateOfBirth { get; set; }

        public string? ResumeFilePath { get; set; }

        [Required(ErrorMessage = "WHO AM i is required")]
        public string WhoAmI { get; set; }
    }
}
