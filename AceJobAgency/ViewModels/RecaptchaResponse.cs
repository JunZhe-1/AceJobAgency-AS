namespace AceJobAgency.viewModels
{
       public class RecaptchaResponse
        {
            public bool Success { get; set; }
            public double Score { get; set; }
            public string Action { get; set; }
            public DateTime Challenge_ts { get; set; }
            public string Hostname { get; set; }
            public List<string> ErrorCodes { get; set; }
        }
}
