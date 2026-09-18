<?php

namespace App\Database;

use Illuminate\Database\PostgresConnection;

/**
 * Keeps boolean bindings valid when PDO emulates prepares for PgBouncer.
 *
 * Emulated prepares are required for older PgBouncer transaction pools, but
 * PDO otherwise renders PHP booleans as integer literals (1/0). PostgreSQL
 * does not allow comparing a boolean column with an integer literal.
 */
class PoolerPostgresConnection extends PostgresConnection
{
    public function prepareBindings(array $bindings)
    {
        foreach ($bindings as $key => $value) {
            if (is_bool($value)) {
                $bindings[$key] = $value ? 'true' : 'false';
            }
        }

        return parent::prepareBindings($bindings);
    }
}
