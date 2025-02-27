using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TrackerAppService
{
    /// <summary>
    /// Process Services interface.
    /// </summary>
    public interface IProcessServices
    {
        #region Methods

        bool StartProcessAsCurrentUser(
            string processCommandLine,
            string processWorkingDirectory = null,
            Process userProcess = null);

        #endregion
    }
}
