#include <iostream>
#include <pqxx/pqxx>


#ifdef WIN32
#pragma comment(lib, "Ws2_32.lib")
#endif

int main()
{
    try
    {
        // Connect to the database.  You can have multiple connections open
        // at the same time, even to the same database.
        pqxx::connection c("host=localhost port=5432 dbname=dvdrental user=postgres password=bingfao");
        std::cout << "Connected to " << c.dbname() << '\n';

#ifdef KX_TEST_0
        // Start a transaction.  A connection can only have one transaction
        // open at the same time, but after you finish a transaction, you
        // can start a new one on the same connection.
        pqxx::work tx{c};

        // Query data of two columns, converting them to std::string and
        // int respectively.  Iterate the rows.
        for (auto [city, temp_hi] : tx.query<std::string, int>(
                 "SELECT city, temp_hi FROM weather ORDER BY city"))
        {
            std::cout << city << " temp_hi " << temp_hi << ".\n";
        }

        // For large amounts of data, "streaming" the results is more
        // efficient.  It does not work for all types of queries though.
        //
        // You can read fields as std::string_view here, which is not
        // something you can do in most places.  A string_view becomes
        // meaningless when the underlying string ceases to exist.  In this
        // one situation, you can convert a field to string_view and it
        // will be valid for just that one iteration of the loop.  The next
        // iteration may overwrite or deallocate its buffer space.
        for (auto [city, temp_hi] : tx.stream<std::string_view, int>(
                 "SELECT city, temp_hi FROM weather"))
        {
            std::cout << city << " temp_hi " << temp_hi << ".\n";
        }

        // Execute a statement, and check that it returns 0 rows of data.
        // This will throw pqxx::unexpected_rows if the query returns rows.
        std::cout << "updatding weathre set temp_hi ...\n";
        tx.exec("UPDATE weather SET temp_hi = temp_lo + 40 where city = 'San Francisco'");

        // If you need to access the result metadata, not just the actual
        // field values, use the "exec" functions.  Most of them return
        // pqxx::result objects.
        pqxx::result res = tx.exec("SELECT * FROM weather");
        std::cout << "Columns:\n";
        for (pqxx::row_size_type col = 0; col < res.columns(); ++col)
            std::cout << res.column_name(col) << '\n';

        // Commit the transaction.  If you don't do this, the database will
        // undo any changes you made in the transaction.
        std::cout << "Making changes definite: ";
        tx.commit();
        std::cout << "OK.\n";
#else
        pqxx::work tx{c};
        tx.exec("Insert into devStatus (devId,devType,devStatus,stTime) values (10001,2,'\\xAD9F2815','2024-09-13 16:00:01')");
        tx.commit();
        std::cout << "OK.\n";
#endif
    }
    catch (std::exception const &e)
    {
        std::cerr << "ERROR: " << e.what() << '\n';
        return 1;
    }
    return 0;
}

// cl /EHsc /std:c++20 -D WIN32 -D_WIN32_WINNT=0x0601 ./pgdbtest.cpp .\pqxx.lib  -ID:\\workspace\\libpqxx\\include -ID:\\workspace\\libpqxx\\build\\include  libpq.lib