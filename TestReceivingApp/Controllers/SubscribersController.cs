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
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.NotFound)); 
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
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.BadRequest)); 
            }
        }

        [Authorize]
        public Subscriber Delete(string email)
        {
            var subscriber = (from s in Subscribers where s.Email == email select s).FirstOrDefault();

            if (subscriber != null)
            {
                Subscribers.RemoveAll(s => s.Email == email);
                return subscriber;
            }
            else
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.NotFound)); 
            }
        }
    }
}
