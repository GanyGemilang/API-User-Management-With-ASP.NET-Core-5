using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace api.usermanagement.Models
{
    public class InsertLogin
    {
        public string username { get; set; }
        public bool online { get; set; }
        public string token { get; set; }
        public DateTime expiredToken { get; set; }
    }
}
