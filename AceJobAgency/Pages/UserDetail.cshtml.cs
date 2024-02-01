using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using WebApplication3.Model;
using WebApplication3.Pages;
using WebApplication3.ViewModels;
using AceJobAgency.viewModels;
using static System.Net.WebRequestMethods;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using AceJobAgency.ViewModels;

namespace AceJobAgency.Pages
{
    public class UserDetailModel : PageModel { 

        private readonly IHttpContextAccessor _context;
        private readonly ILogger<UserDetailModel> _logger;
        private SignInManager<IdentityUser> signInManager { get; }

        public UserDetailModel(
           IHttpContextAccessor dbContext,
           ILogger<UserDetailModel> logger,
           SignInManager<IdentityUser> signInManager)
        {
            this._context = dbContext;
            this._logger = logger;
            this.signInManager = signInManager;


        }


        public async Task<IActionResult> Onget()
        {
            _logger.LogInformation("this is user session id", _context.HttpContext.Session.GetString("SessionId"));

            if (_context.HttpContext.Session.GetString("SessionId") == null)
            {
                _logger.LogInformation("Your session has no session id ");
                await signInManager.SignOutAsync();
                return RedirectToPage("Login");

            }

            //// Check if the user is authenticated
            //else if (TempData.TryGetValue("SessionTerminated", out var sessionTerminated) && (bool)sessionTerminated)
            //{
            //    _logger.LogInformation($"Terminate in user detail");

            //    return RedirectToPage("Login");
            //}

            var sessionTimeoutSeconds = _context.HttpContext.Session.GetInt32("UserSessionTimeout");
            _logger.LogInformation($"Time remainning: {sessionTimeoutSeconds}");


            var currentTime = DateTimeOffset.Now.ToUnixTimeSeconds();
            var lastActivityTime = _context.HttpContext.Session.GetInt32("LastActivityTime") ?? currentTime;

            if (sessionTimeoutSeconds.HasValue && (currentTime - lastActivityTime) > sessionTimeoutSeconds)
            {
                _context.HttpContext.Session.Clear();

                foreach (var key in _context.HttpContext.Session.Keys)
                {
                    _context.HttpContext.Session.Remove(key);
                }
                await signInManager.SignOutAsync();

                _logger.LogInformation($"Your Session has expired");

                return RedirectToPage("Login");
            }
            else
            {
                _context.HttpContext.Session.SetInt32("LastActivityTime", (int)currentTime);

                // Continue processing for an active session
                // _context.HttpContext.Session.SetInt32("StudentId", 50);
            }

            var userEmail = _context.HttpContext.Session.GetString("User_Email");

            return Page();  // Continue processing for the active session
        }


        public async Task<IActionResult> OnPostAsync()
        {
            
            return Page();
        }
      
    }
}
