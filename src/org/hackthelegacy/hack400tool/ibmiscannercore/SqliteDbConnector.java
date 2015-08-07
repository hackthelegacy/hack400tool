//    "hack400tool"
//    - security handling tools for IBM Power Systems (formerly known as AS/400)
//    Copyright (C) 2010-2015  Bart Kulach
//    This file, SqliteDbConnector.java, is part of hack400tool package.

//    "hack400tool" is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.

//    "hack400tool" is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.

//   You should have received a copy of the GNU General Public License
//    along with this program.  If not, see <http://www.gnu.org/licenses/>.
package org.hackthelegacy.hack400tool.ibmiscannercore;

import java.sql.*;
import javax.swing.DefaultListModel;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.table.DefaultTableModel;
import java.util.Vector;

public class SqliteDbConnector {

    private Connection dbConnection = null;
    

    public SqliteDbConnector(String dbName){
        try{
            Class.forName("org.sqlite.JDBC");
            dbConnection = DriverManager.getConnection("jdbc:sqlite:"+dbName);                    
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
    
    public Query query(String queryString) throws SQLException {
        return new Query(queryString);
    }
    
    public class Query {

        private PreparedStatement statement = null;
        public ResultSet resultSet = null;
        
        
        Query(String queryString) throws SQLException {
            String tmpQuery;
            
            if (queryString.toUpperCase().startsWith("SELECT") || 
                queryString.toUpperCase().startsWith("INSERT") ||
                queryString.toUpperCase().startsWith("UPDATE") ||
                queryString.toUpperCase().startsWith("DELETE")) {
                statement = dbConnection.prepareStatement(queryString);
                resultSet = statement.executeQuery();
            } else {
                statement = dbConnection.prepareStatement(
                        "SELECT sqlcommand FROM sqlcommands WHERE id = ? LIMIT 1;");
                statement.setString(1, queryString);
                resultSet = statement.executeQuery();                
                if (resultSet != null) {
                    tmpQuery = resultSet.getString(1);
                    statement = dbConnection.prepareStatement(tmpQuery);
                    resultSet = statement.executeQuery();
                }
            }                    
        }               
        
        public DefaultTableModel toTableModel() throws SQLException {

            if (resultSet == null || dbConnection == null) 
                return null;
            
            ResultSetMetaData metaData = resultSet.getMetaData();
            int numberOfColumns = metaData.getColumnCount();
            Vector columnNames = new Vector();

            for (int column = 0; column < numberOfColumns; column++) {
                columnNames.addElement(metaData.getColumnLabel(column + 1));
            }

            Vector rows = new Vector();

            while (resultSet.next()) {
                Vector newRow = new Vector();

                for (int i = 1; i <= numberOfColumns; i++) {
                    newRow.addElement(resultSet.getObject(i));
                }

                rows.addElement(newRow);
            }
            
            DefaultTableModel resultTableModel = new DefaultTableModel(rows, columnNames);

            return resultTableModel;
        }
        
        public DefaultListModel toListModel() throws SQLException {
        //Note: The assumption is that the list elements reside in the last column
            
            if (resultSet == null || dbConnection == null) 
                return null;            
            
            DefaultListModel resultListModel = new DefaultListModel();
            
            ResultSetMetaData metaData = resultSet.getMetaData();
            int maxColumns = metaData.getColumnCount();
            
            
            while (resultSet.next()) {                
                resultListModel.addElement(resultSet.getObject(maxColumns));
            }

            return resultListModel;
        }
        
        public DefaultTreeModel toTreeModel() throws SQLException {
        //Note: the table has to have first 2 rows of type integer, named (id, parentid)

            if (resultSet == null || dbConnection == null) 
                return null;
            
            DefaultTreeModel resultTreeModel = new DefaultTreeModel(new DefaultMutableTreeNode("Resultset"));
            return resultTreeModel;
        }
        
    }
}
