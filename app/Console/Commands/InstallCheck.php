<?php namespace Choose\Console\Commands;

use Illuminate\Console\Command;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Input\InputArgument;

class InstallCheck extends Command {

	/**
	 * The console command name.
	 *
	 * @var string
	 */
	protected $name = 'install:check';

	/**
	 * The console command description.
	 *
	 * @var string
	 */
	protected $description = 'Command description.';

	/**
	 * Create a new command instance.
	 *
	 * @return void
	 */
	public function __construct()
	{
		parent::__construct();
	}

	/**
	 * Execute the console command.
	 *
	 * @return mixed
	 */
	public function fire()
	{
		print json_encode([
            'content-1' => "<h2>Meet the Team</h2>
<p><b>The choose Leads team is happy, passionate and creative, yet focused.</b></p>
<p>We have one aim; to ensure the leads we sell to you are perfect for your needs, and that the Choose Leads Angels provide the best account management and consultancy in the industry.</p>
<p>The company was founded in 2012, and has gone from strength to strength.</p>
<p>With the launch of our CLV survey call centre in 2014, and the CLV Dynamix Packages, we believe we can be 'outstanding' across the board for both data, and customer services.</p>",
        ]);




	}

}
