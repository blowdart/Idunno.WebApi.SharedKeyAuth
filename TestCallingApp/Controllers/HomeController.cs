using System.Net.Http;
using System.Web.Mvc;

using Idunno.WebApi.SharedKeyAuthentication;

using TestCallingApp.Models;

namespace TestCallingApp.Controllers
{
    public class HomeController : Controller
    {
        //
        // GET: /Home/

        public ActionResult Index()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Subscribe(string name, string email)
        {
            var subscriber = new Subscriber { Name = name, Email = email };

            var client =
                new HttpClient(
                    new SharedKeySigningHandler(Properties.Settings.Default.accountName, Properties.Settings.Default.secretKey));

            var response = client.PostAsJsonAsync("http://localhost:9001/api/Subscribers", subscriber).Result;

            return RedirectToAction("Index");
        }
    }
}
