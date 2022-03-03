using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace HCPortalWebApi.Models
{
    public class ResponseModel
    {
        public string Code { get; set; }
        public string Status { get; set; }
        public string Message { get; set; }
        public object Data { get; set; }
    }
}
