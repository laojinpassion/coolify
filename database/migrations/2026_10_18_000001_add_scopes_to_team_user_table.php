<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Add optional per-membership scopes to team members, so a member can be
     * limited to a single project (or a single environment inside a project)
     * instead of the whole team. NULL columns mean "no restriction", which
     * keeps existing memberships behaving exactly as before.
     */
    public function up(): void
    {
        Schema::table('team_user', function (Blueprint $table) {
            $table->foreignId('project_id')->nullable()->after('role');
            $table->foreignId('environment_id')->nullable()->after('project_id');

            $table->index(['project_id']);
            $table->index(['environment_id']);
        });
    }

    public function down(): void
    {
        Schema::table('team_user', function (Blueprint $table) {
            $table->dropIndex(['project_id']);
            $table->dropIndex(['environment_id']);
            $table->dropColumn(['project_id', 'environment_id']);
        });
    }
};
