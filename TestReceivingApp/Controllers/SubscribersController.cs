using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

using TestReceivingApp.Models;

namespace TestReceivingApp.Controllers
{
    public class SubscribersController : ApiController    
    {
        private static readonly List<Subscriber> Subscribers = new List<Subscriber>();

        public IEnumerable<Subscriber> Get()
        {
            return Subscribers.AsEnumerable();
        }

        public Subscriber Get(string email)
        {
            var subscriber = (from s in Subscribers where s.Email == email select s).FirstOrDefault();
            if (subscriber == null)
            {
                throw new HttpResponseException(Request.CreateResponse(HttpStatusCode.NotFound));
            }

            return subscriber;
        }

        // POST api/values
        [Authorize]
        public HttpResponseMessage Post(Subscriber subscriber)
        {
            if (ModelState.IsValid && !(from s in Subscribers where s.Email == subscriber.Email select s).Any())
            {
                subscriber.CreatedOn = DateTime.UtcNow;
                subscriber.CreatedBy = User.Identity.Name;

                Subscribers.Add(subscriber);

                HttpResponseMessage response = Request.CreateResponse(HttpStatusCode.Created, subscriber);
                response.Headers.Location = new Uri(Url.Link("DefaultApi", new { email = subscriber.Email }));

                return response;
            }
            else
            {
                return Request.CreateResponse(HttpStatusCode.BadRequest);
            }
        }
    }
}
