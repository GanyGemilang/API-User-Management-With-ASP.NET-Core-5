using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace HCPortalWebAPI
{
    public class Connectionstring
    {
        public string Value { get; set; }
        public Connectionstring(string value)
        {
            Value = value;
        }
    }
}
