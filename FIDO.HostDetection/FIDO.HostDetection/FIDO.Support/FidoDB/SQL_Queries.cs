/*
 *
 *  Copyright 2015 Netflix, Inc.
 *
 *     Licensed under the Apache License, Version 2.0 (the "License");
 *     you may not use this file except in compliance with the License.
 *     You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 *
 */

using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Globalization;
using System.Linq;
using System.Net;
using FIDO.HostDetection.FIDO.Support.API.Endpoints;
using FIDO.HostDetection.FIDO.Support.ErrorHandling;
using FIDO.HostDetection.FIDO.Support.Rest;
using Newtonsoft.Json;

namespace Fido_Main.Fido_Support.FidoDB
{
  class SQL_Queries
  {
    //get sql sources from fido XML
    public static SqlObject GetSqlSources()
    {
      var sSQLSources = GetSQLLabels();
      return sSQLSources;
    }

    private static SqlObject GetSQLLabels()
    {
      var query = API_Endpoints.PrimaryConfig.host + API_Endpoints.PrimaryConfig.fido_configs_sysmgmt.sysmgmt.labels;
      var alertRequest = (HttpWebRequest)WebRequest.Create(query);
      var stringreturn = string.Empty;
      var cdbReturn = new SqlObject();
      var getREST = new Fido_Rest_Connection();
      stringreturn = getREST.RestCall(alertRequest);
      cdbReturn = JsonConvert.DeserializeObject<SqlObject>(stringreturn);
      return cdbReturn;
    }

    public static SqlObject GetSQLConfigs()
    {
      var query = API_Endpoints.PrimaryConfig.host + API_Endpoints.PrimaryConfig.fido_configs_sysmgmt.sysmgmt.sql;
      var alertRequest = (HttpWebRequest)WebRequest.Create(query);
      var stringreturn = string.Empty;
      var cdbReturn = new SqlObject();
      var getREST = new Fido_Rest_Connection();
      stringreturn = getREST.RestCall(alertRequest);
      cdbReturn = JsonConvert.DeserializeObject<SqlObject>(stringreturn);
      return cdbReturn;
    }

    public class SqlObject
    {
      public int total_rows { get; set; }
      public int offset { get; set; }
      public List<Row> rows { get; set; }

      public class Query
      {
        public string queryip { get; set; }
        public string queryhostname { get; set; }
        public string querycb { get; set; }
        public string querysent { get; set; }
        public string queryvuln { get; set; }
        public string querycritvuln { get; set; }
        public string queryhighvuln { get; set; }
        public string querylowvuln { get; set; }
      }

      public class Configs
      {
        public string connstring { get; set; }
        public string username { get; set; }
        public string pwd { get; set; }
        public Query query { get; set; }
      }

      public class Value
      {
        public string _id { get; set; }
        public string _rev { get; set; }
        public int type { get; set; }
        public int server { get; set; }
        public string label { get; set; }
        public string vendor { get; set; }
        public Configs configs { get; set; }
      }

      public class Row
      {
        public string id { get; set; }
        public string key { get; set; }
        public Value value { get; set; }
      }
    }

    //get sql connection string and sql query
    //public static List<string> GetSqlConfigs(string sSource)
    //{
    //  var lQueryConfig = new List<string>();

    //  try
    //  {
    //    lQueryConfig.Add(Object_Fido_Configs.GetAsString("fido.sysmgmt." + sSource + ".sqlconnstring", null));
    //    lQueryConfig.Add(Object_Fido_Configs.GetAsString("fido.sysmgmt." + sSource + ".sqlqueryip", null));
    //    lQueryConfig.Add(Object_Fido_Configs.GetAsString("fido.sysmgmt." + sSource + ".sqlqueryhostname", null));

    //    if (sSource == "jamf")
    //    {
    //      lQueryConfig.Add(Object_Fido_Configs.GetAsString("fido.sysmgmt." + sSource + ".sqlqueryextattrib", null));
    //      lQueryConfig.Add(Object_Fido_Configs.GetAsString("fido.sysmgmt." + sSource + ".sqlqueryos", null));
    //    }
    //  }
    //  catch (Exception e)
    //  {
    //    Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in getsqlconfigs area:" + e);
    //  }
    //  return lQueryConfig;
    //}

    //run microsoft sql query and return data
    public static IEnumerable<string> RunMSsqlQuery(List<string> lSQLInput, string sSrcIP, string sHostname)
    {
      var lHostInfoReturn = new List<string>();
      var sqlConnect = new SqlConnection(lSQLInput[0]);

      try
      {
        sqlConnect.Open();
        var sqlCmd = new SqlCommand();
        string sQuery = null;
        if (sSrcIP != null)
        {
          sQuery = lSQLInput[1].Replace(" + sIP + ", sSrcIP);
          sqlCmd = new SqlCommand(sQuery, sqlConnect);
        }
        else if (sHostname != null)
        {
          sQuery = lSQLInput[2].Replace(" + sHostname + ", sHostname);
          sqlCmd = new SqlCommand(sQuery, sqlConnect);
        }

        SqlDataReader sqlReader = sqlCmd.ExecuteReader();
        var oHostInfoReturn = new object[sqlReader.FieldCount];
        if (sqlReader.HasRows)
        {
          while (sqlReader.Read())
          {
            //ReSharper disable once ReturnValueOfPureMethodIsNotUsed
            //GetValues is used and is assigning values to oHostInfoReturn
            sqlReader.GetValues(oHostInfoReturn);
            var q = oHostInfoReturn.Count();
            for (var i = 0; i < q; i++)
            {
              lHostInfoReturn.Add(oHostInfoReturn[i].ToString());
            }
            sqlReader.Dispose();
            return lHostInfoReturn;
          }
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught running MSSQL query:" + e);
      }
      finally
      {
        sqlConnect.Close();
      }
      lHostInfoReturn.Add("unknown");
      return lHostInfoReturn;
    }

    //run mysql query and return data
    public static IEnumerable<string> RunMysqlQuery(List<string> lSQLInput, string sSrcIP, string sHostname)
    {
      //init local variables
      var lHostInfoReturn = new List<string>();
      var sqlConnect = new MySqlConnection(lSQLInput[0]);

      try
      {
        //open connection using pass SQL
        sqlConnect.Open();
        var sqlCmd = new MySqlCommand();

        //If IP is not empty then use IP based sql query.
        //If hostname is not empty then use host based sql query.
        //Replace inline variable with passed argument
        string sQuery = null;
        if (sSrcIP != null)
        {
          sQuery = lSQLInput[1].Replace(" + sIP + ", sSrcIP).ToString(CultureInfo.InvariantCulture);
          sqlCmd = new MySqlCommand(sQuery, sqlConnect);
        }
        else if (sHostname != null)
        {
          sQuery = lSQLInput[2].Replace(" + sHostname + ", sHostname);
          sqlCmd = new MySqlCommand(sQuery, sqlConnect);
        }

        //Initialize the reader and execute query
        MySqlDataReader sqlReader = sqlCmd.ExecuteReader();

        //If query returns values
        if (sqlReader.HasRows)
        {
          //then create object for total # of return columns
          var oHostInfoReturn = new object[sqlReader.FieldCount];
          while (sqlReader.Read())
          {
            sqlReader.GetValues(oHostInfoReturn);
            var q = oHostInfoReturn.Count();
            //read values into list object
            for (var i = 0; i < q; i++)
            {
              lHostInfoReturn.Add(oHostInfoReturn[i].ToString());
            }
            return lHostInfoReturn;
          }
        }
        //clean up and return list object
        sqlReader.Dispose();
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught running MYSQL query:" + e);
      }
      finally
      {
        sqlConnect.Close();
      }

      //If no values return empty
      lHostInfoReturn.Add("unknown");
      return lHostInfoReturn;
    }
  }
}