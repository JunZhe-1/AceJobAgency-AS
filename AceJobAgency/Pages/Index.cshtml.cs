using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Http;

namespace AceJobAgency.Pages
{
    public class IndexModel : PageModel
    {
        private readonly IHttpContextAccessor _context;

        public IndexModel(IHttpContextAccessor context)
        {
            _context = context;
        }

        public void OnGet()
        {
            var userEmail = HttpContext.Session.GetString("User_Email");
            _context.HttpContext.Session.SetInt32("StudentId", 50);
        }
    }
}
