<?php namespace Choose\Console\Commands;

use Choose\Models\Page;
use Illuminate\Console\Command;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Input\InputArgument;

class InstallContent extends Command
{

    /**
     * The console command name.
     *
     * @var string
     */
    protected $name = 'install:content';

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
        $this->createPage('companyArea', 'thirds', [], [], 3);
        $this->createPage('chooseleads', 'halftext', ['position'=>'left'], [], 4);
        $this->createPage('chooseleadsvoice', 'halftext', ['position'=>'right'], [], 5);
        $this->createPage('clvdynamix', 'halftext', ['position'=>'left'], [], 6);
    }

    protected function createPage($slug, $template, array $options, array $content, $order)
    {
        $page = Page::create([
            'page_slug' => $slug,
            'template'  => $template,
            'options'   => json_encode($options),
            'content'   => json_encode($content),
            'order'     => (int) $order,
        ]);
    }


}
