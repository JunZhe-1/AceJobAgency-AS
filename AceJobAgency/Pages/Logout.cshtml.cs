using AceJobAgency.ViewModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using WebApplication3.Model;

namespace AceJobAgency.Pages
{
    public class LogoutModel : PageModel
    {
        private readonly AuthDbContext _context;
        public LogoutModel(AuthDbContext dbContext)
        {
            _context = dbContext;
        }
        public async void OnGet()
        {
            await HttpContext.SignOutAsync();
            await LogAuditAsync("Logout");
            ClearSession();
        }

        public IActionResult OnPost()
        {
            ClearSession();
            return RedirectToPage("/Login");
        }

        private void ClearSession()
        {
            HttpContext.Session.Clear();
            HttpContext.Session.Remove("User_Email");
            HttpContext.Session.Remove("StudentId");
        }

        private async Task LogAuditAsync(string action)
        {
            // Log user activity to the database
            var auditLog = new AuditLog
            {
                UserId = HttpContext.Session.GetString("User_Email"),
                Timestamp = DateTime.UtcNow,
                Action = action
            };

            _context.AuditLogs.Add(auditLog);
            await _context.SaveChangesAsync();
        }
    }
}
