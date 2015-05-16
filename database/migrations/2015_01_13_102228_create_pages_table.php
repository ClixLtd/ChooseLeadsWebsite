<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreatePagesTable extends Migration {

	/**
	 * Run the migrations.
	 *
	 * @return void
	 */
	public function up()
	{
        Schema::create('pages', function(Blueprint $table)
        {
            $table->string('page_slug')->index()->unique();
            $table->string('template');
            $table->longText('options');
            $table->longText('content');
            $table->integer('order');
            $table->timestamps();
        });
	}

	/**
	 * Reverse the migrations.
	 *
	 * @return void
	 */
	public function down()
	{
        Schema::drop('pages');
	}

}
