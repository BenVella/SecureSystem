using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace BennetVellaSecureSoftware.Models
{
    public class FileCheckActionFilter : ActionFilterAttribute
    {
        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            // Check for paramaters from the action this is attached to
            HttpPostedFileBase fileData = (HttpPostedFileBase)filterContext.ActionParameters["file"];
            if (fileData != null)
            {
                // Read bytes from http input stream
                BinaryReader br = new BinaryReader(fileData.InputStream);
                byte[] binData = br.ReadBytes(16);

                byte[] docx = new byte[] { 80, 75, 3, 4, 20, 0, 6, 0 };
                byte[] pdf = new byte[] { 37, 80, 68, 70 };

                bool isValidDocx = true;
                bool isValidPdf = true;
                for (int i = 0; i < binData.Length; i++)
                {
                    // DocX check
                    if (i < docx.Length && isValidDocx)
                    {
                        if (binData[i] == docx[i])
                            isValidDocx = true;
                        else
                            isValidDocx = false;
                    }

                    if (i < pdf.Length && isValidPdf)
                    {
                        if (binData[i] == pdf[i])
                            isValidPdf = true;
                        else
                            isValidPdf = false;
                    }
                }

                string result = System.Text.Encoding.UTF8.GetString(binData);

                if (isValidDocx || isValidPdf)
                {
                    // Do nothing, let method process upload
                }
                else
                {
                    filterContext.Result = new RedirectResult("http://localhost:56578/Article/IncorrectFormat/");
                }
            }
            else
            {
                filterContext.Result = new RedirectResult("http://localhost:56578/Article/Missing/");
            }
        }
    }
}